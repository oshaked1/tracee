package stackunwind

import (
	"sync"

	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/processmanager"
)

type processInfo struct {
	pid libpf.PID
	// WaitGroup for updates
	wg sync.WaitGroup
	// Mutex to access mappings and exited
	mu sync.RWMutex
	// Process mappings. TODO: change this to interval tree LRU, update entry access times when a stack frame from a certain mapping arrives?
	mappings map[libpf.Address]*processmanager.Mapping
	exited   bool
}

// elfInfoKey represents a unique identifier of an ELF file on disk
type elfInfoKey struct {
	device       uint32
	inode        uint64
	modifiedTime uint64
}

// elfInfo contains cached data from an executable needed for processing mappings.
// A negative cache entry may also be recorded with err set to indicate permanent
// error. This avoids inspection of non-ELF or corrupted files again and again.
type elfInfo struct {
	err           error
	fileID        host.FileID
	addressMapper pfelf.AddressMapper
}

type fileInfo struct {
	path       string
	symbols    *libpf.SymbolMap
	dynSymbols *libpf.SymbolMap
}

func (f *fileInfo) GetPath() string {
	return f.path
}

// procRootOpener implements the ELFOpener interface by opening files using /proc/<pid>/root, resolved using a ContainerPathResolver
type procRootOpener struct {
	resolver *containers.ContainerPathResolver
	mountNS  int
}

func (p procRootOpener) GetHostAbsPath(path string) (string, error) {
	return p.resolver.GetHostAbsPath(path, p.mountNS)
}

func (p procRootOpener) OpenELF(path string) (*pfelf.File, error) {
	absPath, err := p.GetHostAbsPath(path)
	if err != nil {
		return nil, err
	}

	return pfelf.Open(absPath)
}
