package stackunwind

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"sync"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/lpm"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/metrics"
	sdtypes "github.com/open-telemetry/opentelemetry-ebpf-profiler/nativeunwind/stackdeltatypes"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/processmanager/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/rlimit"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/support"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tracer/types"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/constraints"
	"golang.org/x/sys/unix"
)

const (
	// updatePoolWorkers decides how many background workers we spawn to
	// process map-in-map updates.
	updatePoolWorkers = 16
	// updatePoolQueueCap decides the work queue capacity of each worker.
	updatePoolQueueCap = 8
)

// The contents of this file are largely identical to
// github.com/open-telemetry/opentelemetry-ebpf-profiler/processmanager/ebpf.
// The code is reimplemented instead of used directly because opentelemetry
// uses the cilium ebpf package while Tracee uses libbpfgo.
//
// Copyright notice from original package:
//
// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Apache License 2.0.
// See the file "LICENSE" for details.
//

// asyncMapUpdaterPool is a pool of goroutines for doing non-blocking updates
// to BPF maps of the "map-in-map" type.
//
// This is necessary because BPF map-in-map updates have an unusually high
// latency compared to updates on other map types. They aren't computationally
// expensive, but they cause the kernel to call `synchronize_rcu` to ensure
// that the map update is actually in place before returning to user-land:
//
// https://elixir.bootlin.com/linux/v6.6.2/source/kernel/bpf/syscall.c#L142
//
// In the simplest terms `synchronize_rcu` can be thought of like a 15-30ms
// sleep that ensures that a change in memory has propagated into the caches
// of all CPU cores. This means that any map-in-map update through the bpf
// syscall will always take about equally long to return, causing significant
// slowdown during startup.
//
// The use case in our profiling agent really doesn't need these strict sync
// guarantees; we are perfectly happy with the update being performed in an
// eventually consistent fashion. We achieve this by spawning N background
// workers and routing update requests based on the key that is supposed to
// be updated.
//
// The partitioned queue design was chosen over a work-stealing queue to ensure
// that updates on individual keys are executed in sequential order. If we
// didn't do this, it could happen that a previously enqueued and delayed
// deletion is executed after an insertion (that we want to persist) or vice
// versa.
type asyncMapUpdaterPool struct {
	workers []*asyncUpdateWorker
}

// newAsyncMapUpdaterPool creates a new worker pool
func newAsyncMapUpdaterPool(ctx context.Context, numWorkers, workerQueueCapacity int) *asyncMapUpdaterPool {
	pool := &asyncMapUpdaterPool{}
	for i := 0; i < numWorkers; i++ {
		queue := make(chan asyncMapInMapUpdate, workerQueueCapacity)
		worker := &asyncUpdateWorker{ctx: ctx, queue: queue}
		go worker.serve()
		pool.workers = append(pool.workers, worker)
	}
	return pool
}

// EnqueueUpdate routes a map update request to a worker in the pool.
//
// Update requests for the same file ID are guaranteed to always be routed to
// the same worker. An `inner` value of `nil` requests deletion. Ownership of
// the given `inner` map is transferred to the worker pool and `inner` is closed
// by the background worker after the update was executed.
func (p *asyncMapUpdaterPool) EnqueueUpdate(outer *libbpfgo.BPFMap, fileID host.FileID, inner int) {
	workerIdx := uint64(fileID) % uint64(len(p.workers))
	if err := p.workers[workerIdx].ctx.Err(); err != nil {
		logger.Debugw("Skipping inner map update", "fileID", fileID, "error", err)
		return
	}
	p.workers[workerIdx].queue <- asyncMapInMapUpdate{
		Outer:  outer,
		FileID: fileID,
		Inner:  inner,
	}
}

// asyncMapInMapUpdate is an asynchronous update request for a map-in-map BPF map.
type asyncMapInMapUpdate struct {
	Outer  *libbpfgo.BPFMap
	FileID host.FileID
	Inner  int // -1 = delete
}

// asyncUpdateWorker represents a worker in a newAsyncMapUpdaterPool.
type asyncUpdateWorker struct {
	ctx   context.Context
	queue chan asyncMapInMapUpdate
}

// serve is the main loop of an update worker.
func (w *asyncUpdateWorker) serve() {
WorkerLoop:
	for {
		var update asyncMapInMapUpdate
		select {
		case <-w.ctx.Done():
			break WorkerLoop
		case update = <-w.queue:
		}

		var err error
		key := uint64(update.FileID)
		if update.Inner == -1 {
			err = update.Outer.DeleteKey(unsafe.Pointer(&key))
		} else {
			fd := uint32(update.Inner)
			err = update.Outer.Update(unsafe.Pointer(&key),
				unsafe.Pointer(&fd))
			err = errors.Join(err, syscall.Close(int(fd)))
		}

		if err != nil {
			logrus.Warnf("Outer map update failure: %v", err)
		}
	}

	// Shutting down: drain remaining queue capacity & close the inner maps.
	for {
		select {
		case update := <-w.queue:
			_ = syscall.Close(update.Inner)
		default:
			return
		}
	}
}

type ebpfImpl struct {
	bpfModule *libbpfgo.Module

	// Interpreter related eBPF maps
	interpreterOffsets *libbpfgo.BPFMap
	dotnetProcs        *libbpfgo.BPFMap
	perlProcs          *libbpfgo.BPFMap
	pyProcs            *libbpfgo.BPFMap
	hotspotProcs       *libbpfgo.BPFMap
	phpProcs           *libbpfgo.BPFMap
	rubyProcs          *libbpfgo.BPFMap
	v8Procs            *libbpfgo.BPFMap
	apmIntProcs        *libbpfgo.BPFMap

	// Stackdelta and process related eBPF maps
	exeIDToStackDeltaMaps              []*libbpfgo.BPFMap
	exeIDToStackDeltaInnerMapTemplates []*libbpfgo.BPFMap
	stackDeltaPageToInfo               *libbpfgo.BPFMap
	pidPageToMappingInfo               *libbpfgo.BPFMap
	unwindInfoArray                    *libbpfgo.BPFMap
	reportedPIDs                       *libbpfgo.BPFMap

	errCounterLock sync.Mutex
	errCounter     map[metrics.MetricID]int64

	hasGenericBatchOperations bool
	hasLPMTrieBatchOperations bool

	updateWorkers *asyncMapUpdaterPool
}

var outerMapsNames = [...]string{
	"stack_unwind_exe_id_to_8_stack_deltas",
	"stack_unwind_exe_id_to_9_stack_deltas",
	"stack_unwind_exe_id_to_10_stack_deltas",
	"stack_unwind_exe_id_to_11_stack_deltas",
	"stack_unwind_exe_id_to_12_stack_deltas",
	"stack_unwind_exe_id_to_13_stack_deltas",
	"stack_unwind_exe_id_to_14_stack_deltas",
	"stack_unwind_exe_id_to_15_stack_deltas",
	"stack_unwind_exe_id_to_16_stack_deltas",
	"stack_unwind_exe_id_to_17_stack_deltas",
	"stack_unwind_exe_id_to_18_stack_deltas",
	"stack_unwind_exe_id_to_19_stack_deltas",
	"stack_unwind_exe_id_to_20_stack_deltas",
	"stack_unwind_exe_id_to_21_stack_deltas",
}

// Compile time check to make sure ebpfMapsImpl satisfies the interface .
var _ ebpf.EbpfHandler = &ebpfImpl{}

// getEBPFHandler checks if the needed maps for the eBPF handler are available
// and loads their references into a package-internal structure.
//
// It further spawns background workers for deferred map updates; the given
// context can be used to terminate them on shutdown.
func getEBPFHandler(bpfModule *libbpfgo.Module, tracers types.IncludedTracers) (ebpf.EbpfHandler, error) {
	impl := &ebpfImpl{bpfModule: bpfModule}

	var err error

	/*if impl.interpreterOffsets, err = bpfModule.GetMap("su_interp_offs"); err != nil {
		return nil, fmt.Errorf("failed to load bpf map su_interp_offs: %v", err)
	}*/

	if impl.stackDeltaPageToInfo, err = bpfModule.GetMap("su_sd_pg_to_info"); err != nil {
		return nil, fmt.Errorf("failed to load bpf map su_sd_pg_to_info: %v", err)
	}

	if impl.pidPageToMappingInfo, err = bpfModule.GetMap("su_pid_pg_to_mp"); err != nil {
		return nil, fmt.Errorf("failed to load bpf map su_pid_pg_to_mp: %v", err)
	}

	if impl.unwindInfoArray, err = bpfModule.GetMap("su_info_arr"); err != nil {
		return nil, fmt.Errorf("failed to load bpf map su_info_arr: %v", err)
	}

	impl.exeIDToStackDeltaMaps = make([]*libbpfgo.BPFMap, len(outerMapsNames))
	impl.exeIDToStackDeltaInnerMapTemplates = make([]*libbpfgo.BPFMap, len(outerMapsNames))
	for i := support.StackDeltaBucketSmallest; i <= support.StackDeltaBucketLargest; i++ {
		mapName := fmt.Sprintf("su_exe_to_%d_sd", i)
		impl.exeIDToStackDeltaMaps[i-support.StackDeltaBucketSmallest], err = bpfModule.GetMap(mapName)
		if err != nil {
			return nil, fmt.Errorf("failed to load bpf map %s: %v", mapName, err)
		}

		mapName = fmt.Sprintf("su_sd_in_%d_tmpl", i)
		impl.exeIDToStackDeltaInnerMapTemplates[i-support.StackDeltaBucketSmallest], err = bpfModule.GetMap(mapName)
		if err != nil {
			return nil, fmt.Errorf("failed to load bpf map %s: %v", mapName, err)
		}
	}

	if err := probeBatchOperations(libbpfgo.MapTypeHash); err == nil {
		logger.Infow("Supports generic eBPF map batch operations")
		impl.hasGenericBatchOperations = true
	}

	if err := probeBatchOperations(libbpfgo.MapTypeLPMTrie); err == nil {
		logger.Infow("Supports LPM trie eBPF map batch operations")
		impl.hasLPMTrieBatchOperations = true
	}

	if err := populateUnwinderTails(bpfModule, tracers); err != nil {
		return nil, fmt.Errorf("failed to populate stack unwinder program tail calls: %v", err)
	}

	return impl, nil
}

type unwinder struct {
	id       uint32
	progName string
	enabled  bool
}

func populateUnwinderTails(bpfMoudle *libbpfgo.Module, tracers types.IncludedTracers) error {
	enabledUnwindersMap, err := bpfMoudle.GetMap("su_enbld_unwnd")
	if err != nil {
		return err
	}

	for _, progTypeSuffix := range []string{"kp", "tp"} {
		tailMap, err := bpfMoudle.GetMap(fmt.Sprintf("su_progs_%s", progTypeSuffix))
		if err != nil {
			return err
		}

		for _, unwinder := range []unwinder{
			{
				id:       uint32(support.ProgUnwindStop),
				progName: "stack_unwind_stop",
				enabled:  true,
			},
			{
				id:       uint32(support.ProgUnwindNative),
				progName: "stack_unwind_native",
				enabled:  true,
			},
			{
				id:       uint32(support.ProgUnwindHotspot),
				progName: "stack_unwind_hotspot",
				enabled:  tracers.Has(types.HotspotTracer),
			},
			{
				id:       uint32(support.ProgUnwindPerl),
				progName: "stack_unwind_perl",
				enabled:  tracers.Has(types.PerlTracer),
			},
			{
				id:       uint32(support.ProgUnwindPHP),
				progName: "stack_unwind_php",
				enabled:  tracers.Has(types.PHPTracer),
			},
			{
				id:       uint32(support.ProgUnwindPython),
				progName: "stack_unwind_python",
				enabled:  tracers.Has(types.PythonTracer),
			},
			{
				id:       uint32(support.ProgUnwindRuby),
				progName: "stack_unwind_ruby",
				enabled:  tracers.Has(types.RubyTracer),
			},
			{
				id:       uint32(support.ProgUnwindV8),
				progName: "stack_unwind_v8",
				enabled:  tracers.Has(types.V8Tracer),
			},
			{
				id:       uint32(support.ProgUnwindDotnet),
				progName: "stack_unwind_dotnet",
				enabled:  tracers.Has(types.DotnetTracer),
			},
		} {
			if !unwinder.enabled {
				continue
			}

			fullProgName := fmt.Sprintf("%s_%s", unwinder.progName, progTypeSuffix)

			// update enabled unwinders map
			trueVal := uint32(1)
			if err := enabledUnwindersMap.Update(unsafe.Pointer(&unwinder.id), unsafe.Pointer(&trueVal)); err != nil {
				return fmt.Errorf("failed to update enabled unwinders map with unwinder %s (%d): %v", fullProgName, unwinder.id, err)
			}

			// update unwinder tail call maps
			prog, err := bpfMoudle.GetProgram(fullProgName)
			if err != nil {
				return err
			}
			fd := uint32(prog.FileDescriptor())

			err = tailMap.Update(unsafe.Pointer(&unwinder.id), unsafe.Pointer(&fd))
			if err != nil {
				return fmt.Errorf("failed to update unwinder tail map %s with unwinder %s (%d): %v", tailMap.Name(), fullProgName, unwinder.id, err)
			}
		}
	}

	return nil
}

func (impl *ebpfImpl) Run(ctx context.Context) {
	impl.updateWorkers = newAsyncMapUpdaterPool(ctx, updatePoolWorkers, updatePoolQueueCap)
}

// UpdateInterpreterOffsets adds the given moduleRanges to the eBPF map interpreterOffsets.
func (impl *ebpfImpl) UpdateInterpreterOffsets(ebpfProgIndex uint16, fileID host.FileID,
	offsetRanges []util.Range) error {
	/*if offsetRanges == nil {
		return errors.New("offsetRanges is nil")
	}
	for _, offsetRange := range offsetRanges {
		//  The keys of this map are executable-id-and-offset-into-text entries, and
		//  the offset_range associated with them gives the precise area in that page
		//  where the main interpreter loop is located. This is required to unwind
		//  nicely from native code into interpreted code.
		key := uint64(fileID)
		// construct an OffsetRange
		value := make([]byte, 0, 24)
		value = binary.NativeEndian.AppendUint64(value, offsetRange.Start)
		value = binary.NativeEndian.AppendUint64(value, offsetRange.End)
		value = binary.NativeEndian.AppendUint16(value, ebpfProgIndex)
		if err := impl.interpreterOffsets.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0])); err != nil {
			log.Fatalf("Failed to place interpreter range in map: %v", err)
		}
	}*/

	return nil
}

// getInterpreterTypeMap returns the eBPF map for the given typ
// or an error if typ is not supported.
func (impl *ebpfImpl) getInterpreterTypeMap(typ libpf.InterpreterType) (*libbpfgo.BPFMap, error) {
	switch typ {
	case libpf.Dotnet:
		return impl.dotnetProcs, nil
	case libpf.Perl:
		return impl.perlProcs, nil
	case libpf.Python:
		return impl.pyProcs, nil
	case libpf.HotSpot:
		return impl.hotspotProcs, nil
	case libpf.PHP:
		return impl.phpProcs, nil
	case libpf.Ruby:
		return impl.rubyProcs, nil
	case libpf.V8:
		return impl.v8Procs, nil
	case libpf.APMInt:
		return impl.apmIntProcs, nil
	default:
		return nil, fmt.Errorf("type %d is not (yet) supported", typ)
	}
}

// UpdateProcData adds the given PID specific data to the specified interpreter data eBPF map.
func (impl *ebpfImpl) UpdateProcData(typ libpf.InterpreterType, pid libpf.PID,
	data unsafe.Pointer) error {
	logrus.Debugf("Loading symbol addresses into eBPF map for PID %d type %d",
		pid, typ)
	ebpfMap, err := impl.getInterpreterTypeMap(typ)
	if err != nil {
		return err
	}

	pid32 := uint32(pid)
	if err := ebpfMap.Update(unsafe.Pointer(&pid32), data); err != nil {
		return fmt.Errorf("failed to add %v info: %s", typ, err)
	}
	return nil
}

// DeleteProcData removes the given PID specific data of the specified interpreter data eBPF map.
func (impl *ebpfImpl) DeleteProcData(typ libpf.InterpreterType, pid libpf.PID) error {
	logrus.Debugf("Removing symbol addresses from eBPF map for PID %d type %d",
		pid, typ)
	ebpfMap, err := impl.getInterpreterTypeMap(typ)
	if err != nil {
		return err
	}

	pid32 := uint32(pid)
	if err := ebpfMap.DeleteKey(unsafe.Pointer(&pid32)); err != nil {
		return fmt.Errorf("failed to remove info: %v", err)
	}
	return nil
}

// UpdatePidInterpreterMapping updates the eBPF map pidPageToMappingInfo with the
// data required to call the correct interpreter unwinder for that memory region.
func (impl *ebpfImpl) UpdatePidInterpreterMapping(pid libpf.PID, prefix lpm.Prefix,
	interpreterProgram uint8, fileID host.FileID, bias uint64) error {
	// pidPageToMappingInfo is a LPM trie and expects the pid and page
	// to be in big endian format.
	bePid := bits.ReverseBytes32(uint32(pid))
	bePage := bits.ReverseBytes64(prefix.Key)

	// construct a PIDPage
	pidPage := make([]byte, 0, 16)
	pidPage = binary.NativeEndian.AppendUint32(pidPage, support.BitWidthPID+prefix.Length)
	pidPage = binary.NativeEndian.AppendUint32(pidPage, bePid)
	pidPage = binary.NativeEndian.AppendUint64(pidPage, bePage)
	biasAndUnwindProgram, err := support.EncodeBiasAndUnwindProgram(bias, interpreterProgram)
	if err != nil {
		return err
	}

	pidPageMappingInfo := make([]byte, 0, 16)
	pidPageMappingInfo = binary.NativeEndian.AppendUint64(pidPageMappingInfo, uint64(fileID))
	pidPageMappingInfo = binary.NativeEndian.AppendUint64(pidPageMappingInfo, biasAndUnwindProgram)

	return impl.pidPageToMappingInfo.Update(unsafe.Pointer(&pidPage[0]), unsafe.Pointer(&pidPageMappingInfo[0]))
}

// DeletePidInterpreterMapping removes the element specified by pid, prefix and a corresponding
// mapping size from the eBPF map pidPageToMappingInfo. It is normally used when an
// interpreter process dies or a region that formerly required interpreter-based unwinding is no
// longer needed.
func (impl *ebpfImpl) DeletePidInterpreterMapping(pid libpf.PID, prefix lpm.Prefix) error {
	// pidPageToMappingInfo is a LPM trie and expects the pid and page
	// to be in big endian format.
	bePid := bits.ReverseBytes32(uint32(pid))
	bePage := bits.ReverseBytes64(prefix.Key)

	// construct a PIDPage
	pidPage := make([]byte, 0, 16)
	pidPage = binary.NativeEndian.AppendUint32(pidPage, support.BitWidthPID+prefix.Length)
	pidPage = binary.NativeEndian.AppendUint32(pidPage, bePid)
	pidPage = binary.NativeEndian.AppendUint64(pidPage, bePage)

	return impl.pidPageToMappingInfo.DeleteKey(unsafe.Pointer(&pidPage[0]))
}

// CollectMetrics returns gathered errors for changes to eBPF maps.
func (impl *ebpfImpl) CollectMetrics() []metrics.Metric {
	impl.errCounterLock.Lock()
	defer impl.errCounterLock.Unlock()

	counts := make([]metrics.Metric, 0, 7)
	for id, value := range impl.errCounter {
		counts = append(counts, metrics.Metric{
			ID:    id,
			Value: metrics.MetricValue(value),
		})
		// As we don't want to report metrics with zero values on the next call,
		// we delete the entries from the map instead of just resetting them.
		delete(impl.errCounter, id)
	}

	return counts
}

type pidPage []byte

// poolPIDPage caches reusable heap-allocated pidPage instances
// to avoid excessive heap allocations.
var poolPIDPage = sync.Pool{
	New: func() any {
		pidPage := make(pidPage, 16)
		return pidPage
	},
}

// getPIDPage initializes a pidPage instance.
func getPIDPage(pid libpf.PID, prefix lpm.Prefix) pidPage {
	// pid_page_to_mapping_info is an LPM trie and expects the pid and page
	// to be in big endian format.
	pidPage := make([]byte, 0, 16)
	pidPage = binary.NativeEndian.AppendUint32(pidPage, support.BitWidthPID+prefix.Length)
	pidPage = binary.BigEndian.AppendUint32(pidPage, uint32(pid))
	pidPage = binary.BigEndian.AppendUint64(pidPage, prefix.Key)
	return pidPage
}

func populatePIDPage(pidPage pidPage, pid libpf.PID, prefix lpm.Prefix) {
	// pid_page_to_mapping_info is an LPM trie and expects the pid and page
	// to be in big endian format.
	binary.NativeEndian.PutUint32(pidPage[0:4], support.BitWidthPID+prefix.Length)
	binary.BigEndian.PutUint32(pidPage[4:8], uint32(pid))
	binary.BigEndian.PutUint64(pidPage[8:16], prefix.Key)
}

// getPIDPagePooled returns a heap-allocated and initialized pidPage instance.
// After usage, put the instance back into the pool with poolPIDPage.Put().
func getPIDPagePooled(pid libpf.PID, prefix lpm.Prefix) pidPage {
	cPIDPage := poolPIDPage.Get().(pidPage)
	populatePIDPage(cPIDPage, pid, prefix)
	return cPIDPage
}

type pidPageMappingInfo []byte

// poolPIDPageMappingInfo caches reusable heap-allocated pidPageMappingInfo instances
// to avoid excessive heap allocations.
var poolPIDPageMappingInfo = sync.Pool{
	New: func() any {
		pidPageMappingInfo := make(pidPageMappingInfo, 16)
		return pidPageMappingInfo
	},
}

// getPIDPageMappingInfo returns a heap-allocated and initialized pidPageMappingInfo instance.
// After usage, put the instance back into the pool with poolPIDPageMappingInfo.Put().
func getPIDPageMappingInfo(fileID, biasAndUnwindProgram uint64) pidPageMappingInfo {
	cInfo := poolPIDPageMappingInfo.Get().(pidPageMappingInfo)
	binary.NativeEndian.PutUint64(cInfo[0:8], fileID)
	binary.NativeEndian.PutUint64(cInfo[8:16], biasAndUnwindProgram)

	return cInfo
}

// probeBatchOperations tests if the BPF syscall accepts batch operations. It
// returns nil if batch operations are supported for mapType or an error otherwise.
func probeBatchOperations(mapType libbpfgo.MapType) error {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		// In environment like github action runners, we can not adjust rlimit.
		// Therefore we just return false here and do not use batch operations.
		return fmt.Errorf("failed to adjust rlimit: %w", err)
	}
	defer restoreRlimit()

	updates := 5
	keySize := 8
	opts := libbpfgo.BPFMapCreateOpts{
		MapFlags: unix.BPF_F_NO_PREALLOC,
	}

	var keys any
	switch mapType {
	case libbpfgo.MapTypeArray:
		// KeySize for Array maps always needs to be 4.
		keySize = 4
		// Array maps are always preallocated.
		opts.MapFlags = 0
		keys = generateSlice[uint32](updates)
	default:
		keys = generateSlice[uint64](updates)
	}

	probeMap, err := libbpfgo.CreateMap(mapType, "", keySize, 8, updates, &opts)
	if err != nil {
		return fmt.Errorf("failed to create %s map for batch probing: %v",
			mapType, err)
	}
	defer syscall.Close(probeMap.FileDescriptor())

	values := generateSlice[uint64](updates)

	n, err := probeMap.UpdateBatch(unsafe.Pointer(&keys.([]uint64)[0]), unsafe.Pointer(&values[0]), uint32(updates))
	if err != nil {
		// Older kernel do not support batch operations on maps.
		// This is just fine and we return here.
		return err
	}
	if n != uint32(updates) {
		return fmt.Errorf("unexpected batch update return: expected %d but got %d",
			updates, n)
	}

	// Remove the probe entries from the map.
	m, err := probeMap.DeleteKeyBatch(unsafe.Pointer(&keys.([]uint64)[0]), uint32(updates))
	if err != nil {
		return err
	}
	if m != uint32(updates) {
		return fmt.Errorf("unexpected batch delete return: expected %d but got %d",
			updates, m)
	}
	return nil
}

// getMapID returns the mapID number to use for given number of stack deltas.
func getMapID(numDeltas uint32) (uint16, error) {
	significantBits := 32 - bits.LeadingZeros32(numDeltas)
	if significantBits <= support.StackDeltaBucketSmallest {
		return support.StackDeltaBucketSmallest, nil
	}
	if significantBits > support.StackDeltaBucketLargest {
		return 0, fmt.Errorf("no map available for %d stack deltas", numDeltas)
	}
	return uint16(significantBits), nil
}

// getOuterMap is a helper function to select the correct outer map for
// storing the stack deltas based on the mapID.
func (impl *ebpfImpl) getOuterMap(mapID uint16) *libbpfgo.BPFMap {
	if mapID < support.StackDeltaBucketSmallest ||
		mapID > support.StackDeltaBucketLargest {
		return nil
	}
	return impl.exeIDToStackDeltaMaps[mapID-support.StackDeltaBucketSmallest]
}

// RemoveReportedPID removes a PID from the reported_pids eBPF map. The kernel component will
// place a PID in this map before it reports it to Go for further processing.
func (impl *ebpfImpl) RemoveReportedPID(pid libpf.PID) {}

// UpdateUnwindInfo writes UnwindInfo into the unwind info array at the given index
func (impl *ebpfImpl) UpdateUnwindInfo(index uint16, info sdtypes.UnwindInfo) error {
	if uint32(index) >= impl.unwindInfoArray.MaxEntries() {
		return fmt.Errorf("unwind info array full (%d/%d items)",
			index, impl.unwindInfoArray.MaxEntries())
	}

	key := uint32(index)
	// construct an UnwindInfo
	unwindInfo := make([]byte, 12)
	unwindInfo[0] = info.Opcode
	unwindInfo[1] = info.FPOpcode
	unwindInfo[2] = info.MergeOpcode
	binary.NativeEndian.PutUint32(unwindInfo[4:8], uint32(info.Param))
	binary.NativeEndian.PutUint32(unwindInfo[8:12], uint32(info.FPParam))
	return impl.unwindInfoArray.Update(unsafe.Pointer(&key), unsafe.Pointer(&unwindInfo[0]))
}

// UpdateExeIDToStackDeltas creates a nested map for fileID in the eBPF map exeIDTostack_deltas
// and inserts the elements of the deltas array in this nested map. Returns mapID or error.
func (impl *ebpfImpl) UpdateExeIDToStackDeltas(fileID host.FileID, deltas []ebpf.StackDeltaEBPF) (
	uint16, error) {
	numDeltas := len(deltas)
	mapID, err := getMapID(uint32(numDeltas))
	if err != nil {
		return 0, err
	}
	outerMap := impl.getOuterMap(mapID)

	innerMap, err := impl.createNewInnerMap(impl.exeIDToStackDeltaInnerMapTemplates[int(mapID)-support.StackDeltaBucketSmallest])
	if err != nil {
		return 0, fmt.Errorf("failed to create inner map: %v", err)
	}
	defer func() {
		if err = syscall.Close(innerMap.FileDescriptor()); err != nil {
			logrus.Errorf("Failed to close FD of inner map for 0x%x: %v", fileID, err)
		}
	}()

	// We continue updating the inner map after enqueueing the update to the
	// outer map. Both the async update pool and our code below need an open
	// file descriptor to work, and we don't know which will complete first.
	// We thus clone the FD, transfer ownership of the clone to the update
	// pool and continue using our original FD whose lifetime is now no longer
	// tied to the FD used in the updater pool.
	innerMapCloned, err := syscall.Dup(innerMap.FileDescriptor())
	if err != nil {
		return 0, fmt.Errorf("failed to clone inner map: %v", err)
	}

	impl.updateWorkers.EnqueueUpdate(outerMap, fileID, innerMapCloned)

	if impl.hasGenericBatchOperations {
		innerKeys := make([]uint32, numDeltas)
		stackDeltas := make([][]byte, numDeltas)

		// Prepare values for batch update.
		for index, delta := range deltas {
			innerKeys[index] = uint32(index)
			stackDeltas[index] = binary.NativeEndian.AppendUint16(stackDeltas[index], delta.AddressLow)
			stackDeltas[index] = binary.NativeEndian.AppendUint16(stackDeltas[index], delta.UnwindInfo)
		}

		_, err := innerMap.UpdateBatch(
			unsafe.Pointer(&innerKeys[0]),
			unsafe.Pointer(&serializeSliceOfByteSlices(stackDeltas)[0]),
			uint32(numDeltas),
		)
		if err != nil {
			return 0, fmt.Errorf("failed to batch insert %d elements for 0x%x into exeIDTostack_deltas: %v",
				numDeltas, fileID, err)
		}
		return mapID, nil
	}

	innerKey := uint32(0)
	for index, delta := range deltas {
		// construct a StackDelta
		stackDelta := make([]byte, 0, 4)
		stackDelta = binary.NativeEndian.AppendUint16(stackDelta, delta.AddressLow)
		stackDelta = binary.NativeEndian.AppendUint16(stackDelta, delta.UnwindInfo)
		innerKey = uint32(index)
		if err := innerMap.Update(unsafe.Pointer(&innerKey), unsafe.Pointer(&stackDelta[0])); err != nil {
			return 0, fmt.Errorf("failed to insert element %d for 0x%x into exeIDTostack_deltas: %v",
				index, fileID, err)
		}
	}

	return mapID, nil
}

// createNewInnerMap creates a new map using the given inner map temaplate name
func (impl *ebpfImpl) createNewInnerMap(templateMap *libbpfgo.BPFMap) (*libbpfgo.BPFMapLow, error) {
	info, err := libbpfgo.GetMapInfoByFD(templateMap.FileDescriptor())
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	btfFD, err := libbpfgo.GetBTFFDByID(info.BTFID)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}
	defer syscall.Close(btfFD)

	opts := &libbpfgo.BPFMapCreateOpts{
		BTFFD:                 uint32(btfFD),
		BTFKeyTypeID:          info.BTFKeyTypeID,
		BTFValueTypeID:        info.BTFValueTypeID,
		BTFVmlinuxValueTypeID: info.BTFVmlinuxValueTypeID,
		MapFlags:              info.MapFlags,
		MapExtra:              info.MapExtra,
		MapIfIndex:            info.IfIndex,
	}

	// TODO: check if this is necessary
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return nil, fmt.Errorf("failed to increase rlimit: %v", err)
	}
	defer restoreRlimit()

	newInnerMap, err := libbpfgo.CreateMap(
		templateMap.Type(),
		"su_sd_inner",
		templateMap.KeySize(),
		templateMap.ValueSize(),
		int(templateMap.MaxEntries()),
		opts,
	)
	if err != nil {
		return nil, errfmt.WrapError(err)
	}

	return newInnerMap, nil
}

// DeleteExeIDToStackDeltas removes all eBPF stack delta entries for given fileID and mapID number.
func (impl *ebpfImpl) DeleteExeIDToStackDeltas(fileID host.FileID, mapID uint16) error {
	outerMap := impl.getOuterMap(mapID)
	if outerMap == nil {
		return fmt.Errorf("invalid mapID %d", mapID)
	}

	// Deleting the entry from the outer maps deletes also the entries of the inner
	// map associated with this outer key.
	//impl.updateWorkers.EnqueueUpdate(outerMap, fileID, nil)
	impl.updateWorkers.EnqueueUpdate(outerMap, fileID, -1)

	return nil
}

// UpdateStackDeltaPages adds fileID/page with given information to eBPF map. If the entry exists,
// it will return an error. Otherwise the key/value pairs will be appended to the hash.
func (impl *ebpfImpl) UpdateStackDeltaPages(fileID host.FileID, numDeltasPerPage []uint16,
	mapID uint16, firstPageAddr uint64) error {
	firstDelta := uint32(0)
	keys := make([][]byte, len(numDeltasPerPage))
	values := make([][]byte, len(numDeltasPerPage))

	// Prepare the key/value combinations that will be loaded.
	for pageNumber, numDeltas := range numDeltasPerPage {
		pageAddr := firstPageAddr + uint64(pageNumber)<<support.StackDeltaPageBits
		// construct a StackDeltaPageKey
		keys[pageNumber] = binary.NativeEndian.AppendUint64(keys[pageNumber], uint64(fileID))
		keys[pageNumber] = binary.NativeEndian.AppendUint64(keys[pageNumber], pageAddr)
		// construct a StackDeltaPageInfo
		values[pageNumber] = binary.NativeEndian.AppendUint32(values[pageNumber], firstDelta)
		values[pageNumber] = binary.NativeEndian.AppendUint16(values[pageNumber], numDeltas)
		values[pageNumber] = binary.NativeEndian.AppendUint16(values[pageNumber], mapID)
		firstDelta += uint32(numDeltas)
	}

	if impl.hasGenericBatchOperations {
		_, err := impl.stackDeltaPageToInfo.UpdateBatch(
			unsafe.Pointer(&serializeSliceOfByteSlices(keys)[0]),
			unsafe.Pointer(&serializeSliceOfByteSlices(values)[0]),
			uint32(len(numDeltasPerPage)),
		)
		return err
	}

	for index := range keys {
		if err := impl.stackDeltaPageToInfo.Update(unsafe.Pointer(&keys[index][0]),
			unsafe.Pointer(&values[index][0])); err != nil {
			return err
		}
	}
	return nil
}

// DeleteStackDeltaPage removes the entry specified by fileID and page from the eBPF map.
func (impl *ebpfImpl) DeleteStackDeltaPage(fileID host.FileID, page uint64) error {
	// construct a StackDeltaPageKey
	stackDeltaPageKey := make([]byte, 0, 16)
	stackDeltaPageKey = binary.NativeEndian.AppendUint64(stackDeltaPageKey, uint64(fileID))
	stackDeltaPageKey = binary.NativeEndian.AppendUint64(stackDeltaPageKey, page)
	return impl.stackDeltaPageToInfo.DeleteKey(unsafe.Pointer(&stackDeltaPageKey[0]))
}

// UpdatePidPageMappingInfo adds the pid and page combination with a corresponding fileID and
// bias as value to the eBPF map pid_page_to_mapping_info.
// Given a PID and a virtual address, the native unwinder can perform one lookup and obtain both
// the fileID of the text section that is mapped at this virtual address, and the offset into the
// text section that this page can be found at on disk.
// If the key/value pair already exists it will return an error.
func (impl *ebpfImpl) UpdatePidPageMappingInfo(pid libpf.PID, prefix lpm.Prefix, fileID, bias uint64) error {
	biasAndUnwindProgram, err := support.EncodeBiasAndUnwindProgram(bias, support.ProgUnwindNative)
	if err != nil {
		return err
	}

	cKey := getPIDPagePooled(pid, prefix)
	defer poolPIDPage.Put(cKey)

	cValue := getPIDPageMappingInfo(fileID, biasAndUnwindProgram)
	defer poolPIDPageMappingInfo.Put(cValue)

	return impl.pidPageToMappingInfo.Update(unsafe.Pointer(&cKey[0]), unsafe.Pointer(&cValue[0]))
}

// DeletePidPageMappingInfo removes the elements specified by prefixes from eBPF map
// pid_page_to_mapping_info and returns the number of elements removed.
func (impl *ebpfImpl) DeletePidPageMappingInfo(pid libpf.PID, prefixes []lpm.Prefix) (int, error) {
	if impl.hasLPMTrieBatchOperations {
		return impl.DeletePidPageMappingInfoBatch(pid, prefixes)
	}
	return impl.DeletePidPageMappingInfoSingle(pid, prefixes)
}

func (impl *ebpfImpl) DeletePidPageMappingInfoSingle(pid libpf.PID, prefixes []lpm.Prefix) (int, error) {
	var deleted int
	var combinedErrors error
	for _, prefix := range prefixes {
		cKey := getPIDPage(pid, prefix)
		if err := impl.pidPageToMappingInfo.DeleteKey(unsafe.Pointer(&cKey[0])); err != nil {
			combinedErrors = errors.Join(combinedErrors, err)
			continue
		}
		deleted++
	}
	return deleted, combinedErrors
}

func (impl *ebpfImpl) DeletePidPageMappingInfoBatch(pid libpf.PID, prefixes []lpm.Prefix) (int, error) {
	// Prepare all keys based on the given prefixes.
	cKeys := make([][]byte, 0, len(prefixes))
	for _, prefix := range prefixes {
		cKeys = append(cKeys, getPIDPage(pid, prefix))
	}

	deleted, err := impl.pidPageToMappingInfo.DeleteKeyBatch(unsafe.Pointer(&serializeSliceOfByteSlices(cKeys)[0]), uint32(len(cKeys)))
	return int(deleted), err
}

// SupportsGenericBatchOperations returns true if the kernel supports eBPF batch operations
// on hash and array maps.
func (impl *ebpfImpl) SupportsGenericBatchOperations() bool {
	return impl.hasGenericBatchOperations
}

// SupportsLPMTrieBatchOperations returns true if the kernel supports eBPF batch operations
// on LPM trie maps.
func (impl *ebpfImpl) SupportsLPMTrieBatchOperations() bool {
	return impl.hasLPMTrieBatchOperations
}

func serializeSliceOfByteSlices(input [][]byte) []byte {
	s := make([]byte, 0)
	for _, elem := range input {
		s = append(s, elem...)
	}

	return s
}

// generateSlice returns a slice of type T and populates every value with its index.
func generateSlice[T constraints.Unsigned](num int) []T {
	keys := make([]T, num)
	for k := range keys {
		keys[k] = T(k)
	}
	return keys
}
