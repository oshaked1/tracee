package trace

import "fmt"

type StackTrace struct {
	UserStackError   StackTraceError `json:"userStackError"`
	KernelStackError StackTraceError `json:"kernelStackError"`
	UserFrames       []StackFrame    `json:"userFrames"`
	KernelFrames     []StackFrame    `json:"kernelFrames"`
}

type StackTraceError struct {
	ErrorType StackTraceErrorType `json:"-"`
	ErrorName string              `json:"errorName"`
	ErrorDesc string              `json:"errorDesc"`
}

type StackFrame struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type KernelStackFrame struct {
	Address      uint64 `json:"address"`
	SymbolName   string `json:"symbolName"`
	SymbolOffset uint64 `json:"symbolOffset"`
	ModuleName   string `json:"moduleName"`
	ModuleOffset uint64 `json:"moduleOffset"`
}

type NativeStackFrame struct {
	Address      uint64 `json:"address"`
	File         string `json:"file"`
	FileAddress  uint64 `json:"fileAddress"`
	SymbolName   string `json:"symbolName"`
	SymbolOffset uint64 `json:"symbolOffset"`
}

type StackTraceErrorType uint16

const (
	StackTraceErrOk                             StackTraceErrorType = 0
	StackTraceErrUnknown                        StackTraceErrorType = 1
	StackTraceErrUnwinderDisabled               StackTraceErrorType = 10
	StackTraceErrKernelGetStackID               StackTraceErrorType = 1001
	StackTraceErrKernelReadStack                StackTraceErrorType = 1002
	StackTraceErrKernelDecodeStack              StackTraceErrorType = 1003
	StackTraceErrNativeLookupTextSection        StackTraceErrorType = 4000
	StackTraceErrNativeLookupStackDeltaInnerMap StackTraceErrorType = 4002
	StackTraceErrNativePCRead                   StackTraceErrorType = 4007
	StackTraceErrNativeStackDeltaInvalid        StackTraceErrorType = 4005
	StackTraceErrNativeNoPIDPageMapping         StackTraceErrorType = 4012
	StackTraceErrNativeZeroPC                   StackTraceErrorType = 4013
)

var StackTraceErrorNames = map[StackTraceErrorType]string{
	StackTraceErrOk:                             "ERR_OK",
	StackTraceErrUnknown:                        "ERR_UNKNOWN",
	StackTraceErrUnwinderDisabled:               "ERR_UNWINDER_DISABLED",
	StackTraceErrKernelGetStackID:               "ERR_KERNEL_GET_STACK_ID",
	StackTraceErrKernelReadStack:                "ERR_KERNEL_READ_STACK",
	StackTraceErrKernelDecodeStack:              "ERR_KERNEL_DECODE_STACK",
	StackTraceErrNativeLookupTextSection:        "ERR_NATIVE_LOOKUP_TEXT_SECTION",
	StackTraceErrNativeLookupStackDeltaInnerMap: "ERR_NATIVE_LOOKUP_STACK_DELTA_INNER_MAP",
	StackTraceErrNativePCRead:                   "ERR_NATIVE_PC_READ",
	StackTraceErrNativeStackDeltaInvalid:        "ERR_NATIVE_STACK_DELTA_INVALID",
	StackTraceErrNativeNoPIDPageMapping:         "ERR_NATIVE_NO_PID_PAGE_MAPPING",
	StackTraceErrNativeZeroPC:                   "ERR_NATIVE_ZERO_PC",
}

var StackTraceErrorDescriptions = map[StackTraceErrorType]string{
	StackTraceErrOk:                             "Success",
	StackTraceErrUnknown:                        "Unknown error",
	StackTraceErrUnwinderDisabled:               "Unwinder disabled",
	StackTraceErrKernelGetStackID:               "Kernel: Unable to get stackid",
	StackTraceErrKernelReadStack:                "Kernel: Unable to read stack from kernel stack map",
	StackTraceErrKernelDecodeStack:              "Kernel: failed to decode stack trace",
	StackTraceErrNativeLookupTextSection:        "Native: Unable to find the code section in the stack delta page info map",
	StackTraceErrNativeLookupStackDeltaInnerMap: "Native: Unable to look up the inner stack delta map (unknown text section ID)",
	StackTraceErrNativePCRead:                   "Native: Unable to read the next instruction pointer from memory",
	StackTraceErrNativeStackDeltaInvalid:        "Native: The stack delta read from the delta map is marked as invalid",
	StackTraceErrNativeNoPIDPageMapping:         "Native: Unable to locate the PID page mapping for the current instruction pointer",
	StackTraceErrNativeZeroPC:                   "Native: Unexpectedly encountered an instruction pointer of zero",
}

func (e StackTraceErrorType) Name() string {
	name, ok := StackTraceErrorNames[e]
	if !ok {
		return fmt.Sprintf("%d", e)
	}
	return name
}

func (e StackTraceErrorType) Description() string {
	desc, ok := StackTraceErrorDescriptions[e]
	if !ok {
		return fmt.Sprintf("Invalid stack trace error %d", e)
	}
	return desc
}

func (e StackTraceErrorType) GetStructure() StackTraceError {
	return StackTraceError{
		ErrorType: e,
		ErrorName: e.Name(),
		ErrorDesc: e.Description(),
	}
}

func (e StackTraceErrorType) GetStructureWithCustomError(err error) StackTraceError {
	return StackTraceError{
		ErrorType: e,
		ErrorName: e.Name(),
		ErrorDesc: fmt.Sprintf("%s: %v", e.Description(), err),
	}
}
