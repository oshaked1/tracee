package stackunwind

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
)

func (m *Manager) ProcessStackTrace(stackTraceRaw *bufferdecoder.StackTraceRaw) *trace.StackTrace {
	stackTrace := &trace.StackTrace{
		UserStackError:   stackTraceRaw.UserStackError,
		KernelStackError: stackTraceRaw.KernelStackError,
		UserFrames:       make([]trace.StackFrame, 0, len(stackTraceRaw.UserFrames)),
		KernelFrames:     make([]trace.StackFrame, 0, len(stackTraceRaw.KernelFrames)),
	}

	// Iterate over raw user frames in reverse so that the trace is presented as entry point to kernel entry.
	// For each raw frame, convert it into a finalized representation.
	for i := len(stackTraceRaw.UserFrames) - 1; i >= 0; i-- {
		rawFrame := stackTraceRaw.UserFrames[i]
		var frame trace.StackFrame

		fileInfo, hasFileInfo := m.fileInfoCache.Get(rawFrame.FileID)

		switch rawFrame.Type {
		case libpf.NativeFrame:
			data := trace.NativeStackFrame{
				Address:     rawFrame.PC,
				FileAddress: uint64(rawFrame.AddrOrLine),
			}
			if hasFileInfo {
				data.File = fileInfo.GetPath()
				symName, offset, found := fileInfo.symbols.LookupByAddress(libpf.SymbolValue(data.FileAddress))
				if found {
					sym, err := fileInfo.symbols.LookupSymbol(libpf.SymbolName(symName))
					if err != nil {
						found = false
					} else if sym.Address == libpf.SymbolValue(0) {
						found = false
					}
				}
				if !found {
					symName, offset, found = fileInfo.dynSymbols.LookupByAddress(libpf.SymbolValue(data.FileAddress))
					if found {
						sym, err := fileInfo.dynSymbols.LookupSymbol(libpf.SymbolName(symName))
						if err != nil {
							found = false
						} else if sym.Address == libpf.SymbolValue(0) {
							found = false
						}
					}
				}
				if found {
					data.SymbolName = string(symName)
					data.SymbolOffset = uint64(offset)
				}
			}

			frame = trace.StackFrame{
				Type: "Native",
				Data: data,
			}

		default:
			frame = trace.StackFrame{
				Type: fmt.Sprintf("Unknown (%s)", rawFrame.Type.String()),
			}
		}

		stackTrace.UserFrames = append(stackTrace.UserFrames, frame)
	}

	// Iterate over raw kernel frames in reverse so that the trace is presented as kernel entry to eBPF program trigger.
	// For each raw frame, convert it into a finalized representation.
	for i := len(stackTraceRaw.KernelFrames) - 1; i >= 0; i-- {
		rawFrame := stackTraceRaw.KernelFrames[i]
		var frame trace.StackFrame

		data := trace.KernelStackFrame{
			Address: rawFrame.PC,
		}
		// TODO: modify Tracee's ksymbols implementation to allow for getting symbol by address after the symbol's start.
		sym, offset, found := m.kernelSymbols.LookupByAddress(libpf.SymbolValue(data.Address))
		if found {
			data.SymbolName = string(sym)
			data.SymbolOffset = uint64(offset)
		}
		mod, offset, found := m.kernelModules.LookupByAddress(libpf.SymbolValue(data.Address))
		if found {
			data.ModuleName = string(mod)
			data.ModuleOffset = uint64(offset)
		}

		// TODO: keep track of loaded kernel modules and correlate module name to file

		frame = trace.StackFrame{
			Type: "Kernel",
			Data: data,
		}

		stackTrace.KernelFrames = append(stackTrace.KernelFrames, frame)
	}

	return stackTrace
}
