package stackunwind

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/capabilities"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
	"github.com/go-co-op/gocron/v2"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/lpm"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/nativeunwind/elfunwindinfo"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/proc"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/processmanager"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/processmanager/execinfomanager"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tracer/types"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

const (
	// request polling should be frequent so we don't miss stack unwinds because the unwind info is not ready yet
	pollTimeout int = 100

	// maximum number of processes to keep unwind information for
	maxProcesses int = 1024

	// Maximum size of the LRU cache holding the executables' ELF information.
	elfInfoCacheSize = 4096

	// Maximum size of the LRU cache holding file info for trace processing.
	fileInfoCacheSize = 4096

	protExec uint64 = 4

	// Time to hold unwind info for a file with no references before it is removed
	unwindInfoRetentionPeriod = 120 * time.Second
)

// dummyPrefix is the LPM prefix installed to indicate the process is known
var dummyPrefix = lpm.Prefix{Key: 0, Length: 64}

type Manager struct {
	ctx                   context.Context
	bpfModule             *libbpfgo.Module
	requestBuffer         *libbpfgo.PerfBuffer
	requestChan           chan []byte
	lostRequestChan       chan uint64
	ebpfHandler           *ebpfImpl
	pathResolver          *containers.ContainerPathResolver
	executableInfoManager *execinfomanager.ExecutableInfoManager
	kernelSymbols         *libpf.SymbolMap
	kernelModules         *libpf.SymbolMap
	// Tracked processes and their mappings. TODO: perform a lookup whenever a stack trace arrives from a process, to update its access time in the LRU.
	processes *lru.Cache[libpf.PID, *processInfo]
	// Information required for updating process mappings (busy path for every new process mapping). TODO: schedule removals when removing file mappings
	elfInfoCache *lru.Cache[elfInfoKey, *elfInfo]
	// Information required for stack trace processing (non-busy path for every new ELF file). TODO: schedule removals when removing file mappings
	fileInfoCache *lru.Cache[host.FileID, *fileInfo]
	// Scheduler for removing file info
	fileRemoveScheduler gocron.Scheduler
}

func NewManager(bpfModule *libbpfgo.Module, pathResolver *containers.ContainerPathResolver) (*Manager, error) {
	// We will be calling code from opentelemtry-ebpf-profiler, which prints logs using logrus.
	// We want these logs to be converted to our logger's format, so we register a logrus hook.
	registerLogrusHook()

	// no extra tracers, only native
	tracers, err := types.Parse("")
	if err != nil {
		return nil, fmt.Errorf("failed to parse stack unwind tracers: %v", err)
	}

	ebpfHandler, err := getEBPFHandler(bpfModule, tracers)
	if err != nil {
		return nil, fmt.Errorf("failed to create stack unwinding ebpf handler: %v", err)
	}

	eim, err := execinfomanager.NewExecutableInfoManager(elfunwindinfo.NewStackDeltaProvider(), ebpfHandler, tracers)
	if err != nil {
		return nil, err
	}

	var kernelSymbols *libpf.SymbolMap
	var kernelModules *libpf.SymbolMap
	err = capabilities.GetInstance().Specific(
		func() error {
			kernelSymbols, err = proc.GetKallsyms("/proc/kallsyms")
			if err != nil {
				return fmt.Errorf("failed to read kernel symbols: %v", err)
			}
			kernelModules, err = proc.GetKernelModules("/proc/modules", kernelSymbols)
			if err != nil {
				return fmt.Errorf("failed to read kernel modules: %v", err)
			}
			return nil
		},
		cap.SYSLOG,
	)
	if err != nil {
		return nil, err
	}

	elfInfoCache, err := lru.New[elfInfoKey, *elfInfo](elfInfoCacheSize)
	if err != nil {
		return nil, err
	}

	fileInfoCache, err := lru.New[host.FileID, *fileInfo](fileInfoCacheSize)
	if err != nil {
		return nil, err
	}

	fileRemoveScheduler, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}

	m := &Manager{
		bpfModule:             bpfModule,
		requestChan:           make(chan []byte, 100),
		lostRequestChan:       make(chan uint64),
		ebpfHandler:           ebpfHandler.(*ebpfImpl),
		pathResolver:          pathResolver,
		executableInfoManager: eim,
		kernelSymbols:         kernelSymbols,
		kernelModules:         kernelModules,
		elfInfoCache:          elfInfoCache,
		fileInfoCache:         fileInfoCache,
		fileRemoveScheduler:   fileRemoveScheduler,
	}

	m.requestBuffer, err = bpfModule.InitPerfBuf("su_requests", m.requestChan, m.lostRequestChan, 256)
	if err != nil {
		return nil, err
	}

	m.processes, err = lru.NewWithEvict[libpf.PID, *processInfo](maxProcesses, m.removeProcess)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) Run(ctx context.Context) {
	m.ctx = ctx
	m.requestBuffer.Poll(pollTimeout)
	m.ebpfHandler.Run(ctx)
	m.fileRemoveScheduler.Start()

	// TODO: use a worker pool to handle requests
	for {
		select {
		case requestData := <-m.requestChan:
			decoder := bufferdecoder.New(requestData)
			request, err := decoder.DecodeStackUnwindRequest()
			if err != nil {
				logger.Warnw("Error decoding stack unwind info request", "error", err)
				continue
			}
			//logger.Infow(fmt.Sprintf("Stack unwind manager request: %#v", request))
			//logger.Infow("Stack unwind manager request", "pid", request.tgid, "filepath", request.filePath)
			if err := m.handleRequest(request); err != nil {
				logger.Warnw("Error handling stack unwind info request", "error", err)
			}
		case lost := <-m.lostRequestChan:
			logger.Warnw(fmt.Sprintf("lost %d stack unwind info requests", lost))
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *Manager) Stop() error {
	m.requestBuffer.Stop()
	return m.fileRemoveScheduler.Shutdown()
}

func (m *Manager) handleRequest(request *bufferdecoder.UnwindRequest) error {
	// Before doing anything, get the process info to make sure the process hasn't exited already
	processInfo := m.getOrCreateProcessInfo(libpf.PID(request.Pid))
	var exited bool
	processInfo.mu.RLock()
	exited = processInfo.exited
	processInfo.mu.RUnlock()
	if exited {
		return nil
	}

	if request.Type != bufferdecoder.UnwindRequestRemoveProcess {
		processInfo.wg.Add(1)
		defer processInfo.wg.Done()
	}

	switch request.Type {
	case bufferdecoder.UnwindRequestAddFileMapping:
		if err := m.addFileMapping(request, processInfo); err != nil {
			return fmt.Errorf("error adding file mapping: %v", err)
		}
		return nil
	case bufferdecoder.UnwindRequestAddAnonymousMapping:
		return nil
	case bufferdecoder.UnwindRequestRemoveMapping:
		if found, err := m.removeProcessMapping(processInfo, libpf.Address(request.Address)); err != nil {
			return fmt.Errorf("error removing mapping: found: %v, error: %v", found, err)
		}
		return nil
	case bufferdecoder.UnwindRequestRemoveProcess:
		// Mark the process as exited so that no new updates are started
		processInfo.mu.Lock()
		processInfo.exited = true
		processInfo.mu.Unlock()

		// Wait for all in progress updates to finish
		processInfo.wg.Wait()

		// Remove the process and all its mappings
		defer m.processes.Remove(processInfo.pid)
		if err := m.removeProcessMappings(processInfo); err != nil {
			return fmt.Errorf("error removing mappings for PID %d: %v", processInfo.pid, err)
		}
		return nil
	}

	return nil
}

func (m *Manager) getOrCreateProcessInfo(pid libpf.PID) *processInfo {
	info, ok := m.processes.Get(pid)
	if !ok {
		// We don't have information for this process yet
		info = &processInfo{
			pid:      pid,
			mappings: make(map[libpf.Address]*processmanager.Mapping),
		}
		m.processes.Add(pid, info)
	}

	return info
}

func (m *Manager) addFileMapping(request *bufferdecoder.UnwindRequest, processInfo *processInfo) error {
	opener := procRootOpener{resolver: m.pathResolver, mountNS: int(request.MountNS)}
	elfRef := pfelf.NewReference(request.FilePath, opener)
	defer elfRef.Close()

	elfInfo := m.getELFInfo(
		elfRef,
		elfInfoKey{
			device:       request.Device,
			inode:        request.Inode,
			modifiedTime: request.ModifiedTime,
		},
		request.FilePath,
	)
	if elfInfo.err != nil {
		return elfInfo.err
	}

	// get the virtual addresses for this mapping
	elfSpaceVA, ok := elfInfo.addressMapper.FileOffsetToVirtualAddress(request.FileOffset)
	if !ok {
		return fmt.Errorf("failed to map file offset to virtual address: PID %d, file %s, offset %x", request.Pid, request.FilePath, request.FileOffset)
	}

	if err := m.handleNewMapping(
		processInfo,
		&processmanager.Mapping{
			FileID:     elfInfo.fileID,
			Vaddr:      libpf.Address(request.Address),
			Bias:       request.Address - elfSpaceVA,
			Length:     request.Length,
			Device:     uint64(request.Device),
			Inode:      request.Inode,
			FileOffset: request.FileOffset,
		},
		elfRef,
	); err != nil {
		/*if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, execinfomanager.ErrDeferredFileID) {
			//log.Errorf("Failed to handle mapping for PID %d, file %s: %v",
			//	pr.PID(), mapping.Path, err)
			return err
		}*/
		return err
	}

	// Do this last because it's not necessary for unwinding, only for trace processing
	return m.addFileInfo(elfInfo.fileID, elfRef, request.FilePath)
}

func (m *Manager) getELFInfo(elfRef *pfelf.Reference, key elfInfoKey, filePath string) *elfInfo {
	if elfInfo, ok := m.elfInfoCache.Get(key); ok {
		return elfInfo
	}

	elfInfo := &elfInfo{}

	elf, err := elfRef.GetELF()
	if err != nil {
		elfInfo.err = fmt.Errorf("error opening ELF file %s in mount NS 0x%x: %v", filePath, elfRef.ELFOpener.(procRootOpener).mountNS, err)
		// It is possible that the we don't have access to this file. Do not cache these errors.
		if !errors.Is(err, os.ErrNotExist) {
			// Cache the other errors: not an ELF, ELF corrupt, etc.
			// to reduce opening it again and again.
			m.elfInfoCache.Add(key, elfInfo)
		}
		return elfInfo
	}

	elfInfo.fileID = host.FileID(utils.HashFileID(key.device, key.inode, key.modifiedTime))
	elfInfo.addressMapper = elf.GetAddressMapper()

	m.elfInfoCache.Add(key, elfInfo)

	return elfInfo
}

func (m *Manager) handleNewMapping(processInfo *processInfo,
	mapping *processmanager.Mapping, elfRef *pfelf.Reference) error {
	// Update eBPF maps with information about this mapping
	if err := m.addProcessMapping(processInfo, mapping); err != nil {
		return err
	}

	// Generate and update eBPF maps with native unwind info
	_, err := m.executableInfoManager.AddOrIncRef(mapping.FileID, elfRef)
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) addProcessMapping(processInfo *processInfo, mapping *processmanager.Mapping) error {
	// Register the new mapping
	processInfo.mu.Lock()
	processInfo.mappings[mapping.Vaddr] = mapping
	processInfo.mu.Unlock()

	prefixes, err := lpm.CalculatePrefixList(uint64(mapping.Vaddr), uint64(mapping.Vaddr)+mapping.Length)
	if err != nil {
		return fmt.Errorf("failed to create LPM entries for PID %d: %v", processInfo.pid, err)
	}

	for _, prefix := range prefixes {
		if err = m.ebpfHandler.UpdatePidPageMappingInfo(processInfo.pid, prefix, uint64(mapping.FileID),
			mapping.Bias); err != nil {
			return fmt.Errorf(
				"failed to update pid_page_to_mapping_info (pid: %d, page: 0x%x/%d): %v",
				processInfo.pid, prefix.Key, prefix.Length, err)
		}
	}

	return nil
}

func (m *Manager) addFileInfo(fileID host.FileID, elfRef *pfelf.Reference, path string) error {
	// TODO: some symbols are only available via .debug files.
	// These are generally unavailable in containers.
	// Decide if they're important enough, considering they require some extra processing and tracking of build IDs.

	// Check if we already have file info for this file
	if _, ok := m.fileInfoCache.Get(fileID); ok {
		return nil
	}

	fileInfo := &fileInfo{
		path: path,
	}

	var errs error

	elf, err := elfRef.GetELF()
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("error getting ELF file %s: %v", path, err))
	} else {
		// Get symbols and dynamic symbols
		fileInfo.symbols, err = elf.ReadSymbols()
		if err != nil {
			fileInfo.symbols = &libpf.SymbolMap{}
			logger.Debugw("Failed reading symbols", "file", path, "error", err)
		}
		fileInfo.dynSymbols, err = elf.ReadDynamicSymbols()
		if err != nil {
			fileInfo.dynSymbols = &libpf.SymbolMap{}
			logger.Debugw("Failed reading dynamic symbols", "file", path, "error", err)
		}
	}

	m.fileInfoCache.Add(fileID, fileInfo)

	// Check if one of .eh_frame, .debug_frame or .gopclntab sections is present
	if err := elf.LoadSections(); err != nil {
		errs = errors.Join(errs, fmt.Errorf("error loading ELF sections for %s: %v", path, err))
	} else {
		found := false
	loop:
		for _, section := range elf.Sections {
			switch section.Name {
			case ".eh_frame":
				fallthrough
			case ".debug_frame":
				fallthrough
			case ".gopclntab":
				found = true
				break loop
			}
		}

		if !found {
			logger.Errorw("No section containing stack deltas found. Tampered binary?", "file", path, "mount NS", elfRef.ELFOpener.(procRootOpener).mountNS)
		}
	}

	return errs
}

func (m *Manager) removeProcess(pid libpf.PID, info *processInfo) {
	if err := m.removeProcessMappings(info); err != nil {
		logger.Warnw("Error removing mappings for evicted process", "pid", pid, "error", err)
	}
}

func (m *Manager) removeProcessMappings(processInfo *processInfo) error {
	var errs error

	for addr := range processInfo.mappings {
		if _, err := m.removeProcessMapping(processInfo, addr); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func (m *Manager) removeProcessMapping(processInfo *processInfo, address libpf.Address) (bool, error) {
	// Get mapping to remove
	processInfo.mu.RLock()
	mapping, found := processInfo.mappings[address]
	processInfo.mu.RUnlock()
	if !found {
		// Fail silently if there is no mapping at this address
		return found, nil
	}

	prefixes, err := lpm.CalculatePrefixList(uint64(mapping.Vaddr), uint64(mapping.Vaddr)+mapping.Length)
	if err != nil {
		return found, fmt.Errorf("failed to create LPM entries for PID %d: %v", processInfo.pid, err)
	}

	var errs error

	if _, err := m.ebpfHandler.DeletePidPageMappingInfo(processInfo.pid, prefixes); err != nil {
		errs = errors.Join(errs, err)
	}

	_, err = m.fileRemoveScheduler.NewJob(
		gocron.OneTimeJob(gocron.OneTimeJobStartDateTime(time.Now().Add(unwindInfoRetentionPeriod))),
		gocron.NewTask(
			func() {
				if err := m.executableInfoManager.RemoveOrDecRef(mapping.FileID); err != nil {
					logger.Warnw("Error removing file info or decreasing reference for file ID %v: %v", mapping.FileID, err)
				}
			},
		),
	)
	errs = errors.Join(errs, err)

	// Remove the mapping from the process
	processInfo.mu.Lock()
	delete(processInfo.mappings, address)
	processInfo.mu.Unlock()

	return found, errs
}
