// Package bufferdecoder implements simple translation between byte
// sequences and the user-defined structs.
//
// The package favors efficiency over flexibility. The provided API
// allows fast decoding of byte sequence sent by the Tracee eBPF program from
// kernel-space to user-space.
package bufferdecoder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/support"
)

type EbpfDecoder struct {
	buffer []byte
	cursor int
}

var ErrBufferTooShort = errors.New("can't read from buffer: buffer too short")

// New creates and initializes a new EbpfDecoder using rawBuffer as its initial content.
// The EbpfDecoder takes ownership of rawBuffer, and the caller should not use rawBuffer after this call.
// New is intended to prepare a buffer to read existing data from it, translating it to protocol defined structs.
// The protocol is specific between the Trace eBPF program and the Tracee-eBPF user space application.
func New(rawBuffer []byte) *EbpfDecoder {
	return &EbpfDecoder{
		buffer: rawBuffer,
		cursor: 0,
	}
}

// BuffLen returns the total length of the buffer owned by decoder.
func (decoder *EbpfDecoder) BuffLen() int {
	return len(decoder.buffer)
}

// ReadAmountBytes returns the total amount of bytes that decoder has read from its buffer up until now.
func (decoder *EbpfDecoder) ReadAmountBytes() int {
	return decoder.cursor
}

// DecodeContext translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.EventContext struct.
func (decoder *EbpfDecoder) DecodeContext(eCtx *EventContext) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < eCtx.GetSizeBytes() {
		return errfmt.Errorf("context buffer size [%d] smaller than %d", len(decoder.buffer[offset:]), eCtx.GetSizeBytes())
	}

	// event_context start
	eCtx.Ts = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+8])

	// task_context start
	eCtx.StartTime = binary.LittleEndian.Uint64(decoder.buffer[offset+8 : offset+16])
	eCtx.CgroupID = binary.LittleEndian.Uint64(decoder.buffer[offset+16 : offset+24])
	eCtx.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	eCtx.Tid = binary.LittleEndian.Uint32(decoder.buffer[offset+28 : offset+32])
	eCtx.Ppid = binary.LittleEndian.Uint32(decoder.buffer[offset+32 : offset+36])
	eCtx.HostPid = binary.LittleEndian.Uint32(decoder.buffer[offset+36 : offset+40])
	eCtx.HostTid = binary.LittleEndian.Uint32(decoder.buffer[offset+40 : offset+44])
	eCtx.HostPpid = binary.LittleEndian.Uint32(decoder.buffer[offset+44 : offset+48])
	eCtx.Uid = binary.LittleEndian.Uint32(decoder.buffer[offset+48 : offset+52])
	eCtx.MntID = binary.LittleEndian.Uint32(decoder.buffer[offset+52 : offset+56])
	eCtx.PidID = binary.LittleEndian.Uint32(decoder.buffer[offset+56 : offset+60])
	_ = copy(eCtx.Comm[:], decoder.buffer[offset+60:offset+76])
	_ = copy(eCtx.UtsName[:], decoder.buffer[offset+76:offset+92])
	eCtx.Flags = binary.LittleEndian.Uint32(decoder.buffer[offset+92 : offset+96])
	eCtx.LeaderStartTime = binary.LittleEndian.Uint64(decoder.buffer[offset+96 : offset+104])
	eCtx.ParentStartTime = binary.LittleEndian.Uint64(decoder.buffer[offset+104 : offset+112])
	// task_context end

	eCtx.EventID = events.ID(int32(binary.LittleEndian.Uint32(decoder.buffer[offset+112 : offset+116])))
	eCtx.Syscall = int32(binary.LittleEndian.Uint32(decoder.buffer[offset+116 : offset+120]))
	eCtx.Retval = int64(binary.LittleEndian.Uint64(decoder.buffer[offset+120 : offset+128]))
	eCtx.HasStackTrace = binary.LittleEndian.Uint16(decoder.buffer[offset+128:offset+130]) != 0
	eCtx.UserStackError = trace.StackTraceErrorType(binary.LittleEndian.Uint16(decoder.buffer[offset+130 : offset+132]))
	eCtx.ProcessorId = binary.LittleEndian.Uint16(decoder.buffer[offset+132 : offset+134])
	eCtx.PoliciesVersion = binary.LittleEndian.Uint16(decoder.buffer[offset+134 : offset+136])
	eCtx.MatchedPolicies = binary.LittleEndian.Uint64(decoder.buffer[offset+136 : offset+144])
	// event_context end

	decoder.cursor += eCtx.GetSizeBytes()
	return nil
}

// DecodeArguments decodes the remaining buffer's argument values, according to the given event definition.
// It should be called last, and after decoding the argnum with DecodeUint8.
//
// Argument array passed should be initialized with the size of len(evtFields).
func (decoder *EbpfDecoder) DecodeArguments(args []trace.Argument, argnum int, evtFields []trace.ArgMeta, evtName string, eventId events.ID) error {
	for i := 0; i < argnum; i++ {
		idx, arg, err := readArgFromBuff(
			eventId,
			decoder,
			evtFields,
		)
		if err != nil {
			logger.Errorw("error reading argument from buffer", "error", errfmt.Errorf("failed to read argument %d of event %s: %v", i, evtName, err))
			continue
		}
		if args[idx].Value != nil {
			logger.Warnw("argument overridden from buffer", "error", errfmt.Errorf("read more than one instance of argument %s of event %s. Saved value: %v. New value: %v", arg.Name, evtName, args[idx].Value, arg.Value))
		}
		args[idx] = arg
	}

	// Fill missing arguments metadata
	for i := 0; i < len(evtFields); i++ {
		if args[i].Value == nil {
			args[i].ArgMeta = evtFields[i]
			args[i].Value = evtFields[i].Zero
		}
	}
	return nil
}

func (decoder *EbpfDecoder) DecodeStackUnwindRequest() (*UnwindRequest, error) {
	//logger.Infow("request", "size", decoder.BuffLen())
	//return nil, nil
	// Decode request type and build request struct
	var reqType uint32
	if err := decoder.DecodeUint32(&reqType); err != nil {
		return nil, err
	}
	request := &UnwindRequest{
		Type: UnwindRequestType(reqType),
	}

	// Invalid request type
	if request.Type > UnwindMaxRequest {
		return nil, fmt.Errorf("invalid request %d", request.Type)
	}

	// Decode PID (used by all requests)
	if err := decoder.DecodeInt32(&request.Pid); err != nil {
		return nil, err
	}

	// No more information is used by requestRemovePID
	if request.Type == UnwindRequestRemoveProcess {
		return request, nil
	}

	// Decode mapping address (used by all remaining requests)
	if err := decoder.DecodeUint64(&request.Address); err != nil {
		return nil, err
	}

	// No more information is used by requestRemoveMapping
	if request.Type == UnwindRequestRemoveMapping {
		return request, nil
	}

	// Decode mapping length (used by all remaining requests)
	if err := decoder.DecodeUint64(&request.Length); err != nil {
		return nil, err
	}

	// No more information used by requestAddAnonymousMapping
	if request.Type == UnwindRequestAddAnonymousMapping {
		return request, nil
	}

	// Decode the rest of the fiels, used by requestAddFileMapping
	if err := decoder.DecodeUint64(&request.FileOffset); err != nil {
		return nil, err
	}
	if err := decoder.DecodeUint32(&request.MountNS); err != nil {
		return nil, err
	}
	if err := decoder.DecodeUint32(&request.Device); err != nil {
		return nil, err
	}
	if err := decoder.DecodeUint64(&request.Inode); err != nil {
		return nil, err
	}
	if err := decoder.DecodeUint64(&request.ModifiedTime); err != nil {
		return nil, err
	}
	var pathLen uint32
	if err := decoder.DecodeUint32(&pathLen); err != nil {
		return nil, err
	}
	if err := decoder.DecodeString(&request.FilePath, int(pathLen)-1); err != nil { // last character is a NULL terminator
		return nil, err
	}

	return request, nil
}

func getKernelFrames(kernelStacksMap *libbpfgo.BPFMap, kernelStackID int32) ([]StackFrameRaw, trace.StackTraceError) {
	frames := make([]StackFrameRaw, 0, 15) // conservative estimate for the number of kernel stack frames

	stackBytes, err := kernelStacksMap.GetValue(unsafe.Pointer(&kernelStackID))
	if err != nil {
		return frames, trace.StackTraceErrKernelReadStack.GetStructureWithCustomError(err)
	}

	// TODO: keep track of stack IDs in an LRU slightly smaller than the kernel stack map and perform kernel stack map evictions when an LRU stack id is evicted.

	/*defer func() {
		// attempt to remove the ID from the map so we don't fill it up
		if err := kernelStacksMap.DeleteKey(unsafe.Pointer(&kernelStackID)); err != nil {
			logger.Debugw("failed to delete kernel stack from eBPF map", "error", err)
		}
	}()*/

	// Read all stack frames
	decoder := New(stackBytes)
	for _ = range support.PerfMaxStackDepth {
		var val uint64
		if err := decoder.DecodeUint64(&val); err != nil {
			return frames, trace.StackTraceErrKernelDecodeStack.GetStructureWithCustomError(err)
		}

		if val == 0 {
			break
		}

		frames = append(frames, StackFrameRaw{
			PC:   val,
			Type: libpf.KernelFrame,
			// For all kernel frames, the kernel unwinder will always produce a
			// frame in which the RIP is after a call instruction (it hides the
			// top frames that leads to the unwinder itself).
			ReturnAddress: true,
		})
	}

	return frames, trace.StackTraceErrOk.GetStructure()
}

func (decoder *EbpfDecoder) DecodeStackTrace(kernelStacksMap *libbpfgo.BPFMap,
	userStackError trace.StackTraceErrorType) (*StackTraceRaw, error) {
	var err error

	// Decode stack trace metadata
	var kernelStackID int32
	if err = decoder.DecodeInt32(&kernelStackID); err != nil {
		return nil, err
	}
	var userStackLen uint32
	if err = decoder.DecodeUint32(&userStackLen); err != nil {
		return nil, err
	}

	stackTrace := &StackTraceRaw{
		UserStackError: userStackError.GetStructure(),
		UserFrames:     make([]StackFrameRaw, 0, userStackLen),
	}

	// Insert kernel frames
	if kernelStackID >= 0 {
		var err trace.StackTraceError
		stackTrace.KernelFrames, stackTrace.KernelStackError = getKernelFrames(kernelStacksMap, kernelStackID)
		if err.ErrorType != trace.StackTraceErrOk {
			logger.Warnw("Failed to get kernel stack frames", "error", stackTrace.KernelStackError.ErrorDesc)
		}
	} else {
		logger.Warnw("Kernel stack trace failed", "error code", kernelStackID)
		stackTrace.KernelStackError = trace.StackTraceErrKernelGetStackID.GetStructureWithCustomError(
			fmt.Errorf("bpf_get_stackid() returned with error code %d", kernelStackID),
		)
	}

	// Decode user frames
	for _ = range userStackLen {
		var pc uint64
		if err := decoder.DecodeUint64(&pc); err != nil {
			return nil, err
		}
		var fileID uint64
		if err := decoder.DecodeUint64(&fileID); err != nil {
			return nil, err
		}
		var addrOrLine uint64
		if err := decoder.DecodeUint64(&addrOrLine); err != nil {
			return nil, err
		}
		var kindAndReturnAddress uint64
		if err := decoder.DecodeUint64(&kindAndReturnAddress); err != nil {
			return nil, err
		}
		kind := kindAndReturnAddress & 0xff
		returnAddress := (kindAndReturnAddress >> 8) & 0xff
		stackTrace.UserFrames = append(stackTrace.UserFrames, StackFrameRaw{
			PC:            pc,
			FileID:        host.FileID(fileID),
			AddrOrLine:    libpf.AddressOrLineno(addrOrLine),
			Type:          libpf.FrameType(kind),
			ReturnAddress: returnAddress != 0,
		})
	}

	return stackTrace, nil
}

// DecodeUint8 translates data from the decoder buffer, starting from the decoder cursor, to uint8.
func (decoder *EbpfDecoder) DecodeUint8(msg *uint8) error {
	readAmount := 1
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = decoder.buffer[decoder.cursor]
	decoder.cursor += readAmount
	return nil
}

// DecodeInt8 translates data from the decoder buffer, starting from the decoder cursor, to int8.
func (decoder *EbpfDecoder) DecodeInt8(msg *int8) error {
	readAmount := 1
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int8(decoder.buffer[offset])
	decoder.cursor += readAmount
	return nil
}

// DecodeUint16 translates data from the decoder buffer, starting from the decoder cursor, to uint16.
func (decoder *EbpfDecoder) DecodeUint16(msg *uint16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint16(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeUint16BigEndian translates data from the decoder buffer, starting from the decoder cursor, to uint16.
func (decoder *EbpfDecoder) DecodeUint16BigEndian(msg *uint16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.BigEndian.Uint16(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeInt16 translates data from the decoder buffer, starting from the decoder cursor, to int16.
func (decoder *EbpfDecoder) DecodeInt16(msg *int16) error {
	readAmount := 2
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int16(binary.LittleEndian.Uint16(decoder.buffer[offset : offset+readAmount]))
	decoder.cursor += readAmount
	return nil
}

// DecodeUint32 translates data from the decoder buffer, starting from the decoder cursor, to uint32.
func (decoder *EbpfDecoder) DecodeUint32(msg *uint32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeUint32BigEndian translates data from the decoder buffer, starting from the decoder cursor, to uint32.
func (decoder *EbpfDecoder) DecodeUint32BigEndian(msg *uint32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.BigEndian.Uint32(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeInt32 translates data from the decoder buffer, starting from the decoder cursor, to int32.
func (decoder *EbpfDecoder) DecodeInt32(msg *int32) error {
	readAmount := 4
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int32(binary.LittleEndian.Uint32(decoder.buffer[offset : offset+readAmount]))
	decoder.cursor += readAmount
	return nil
}

// DecodeUint64 translates data from the decoder buffer, starting from the decoder cursor, to uint64.
func (decoder *EbpfDecoder) DecodeUint64(msg *uint64) error {
	readAmount := 8
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+readAmount])
	decoder.cursor += readAmount
	return nil
}

// DecodeInt64 translates data from the decoder buffer, starting from the decoder cursor, to int64.
func (decoder *EbpfDecoder) DecodeInt64(msg *int64) error {
	readAmount := 8
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < readAmount {
		return ErrBufferTooShort
	}
	*msg = int64(binary.LittleEndian.Uint64(decoder.buffer[decoder.cursor : decoder.cursor+readAmount]))
	decoder.cursor += readAmount
	return nil
}

// DecodeBool translates data from the decoder buffer, starting from the decoder cursor, to bool.
func (decoder *EbpfDecoder) DecodeBool(msg *bool) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < 1 {
		return ErrBufferTooShort
	}
	*msg = (decoder.buffer[offset] != 0)
	decoder.cursor++
	return nil
}

// DecodeBytes copies from the decoder buffer, starting from the decoder cursor, to msg, size bytes.
func (decoder *EbpfDecoder) DecodeBytes(msg []byte, size int) error {
	offset := decoder.cursor
	bufferLen := len(decoder.buffer[offset:])
	if bufferLen < size {
		return ErrBufferTooShort
	}
	_ = copy(msg[:], decoder.buffer[offset:offset+size])
	decoder.cursor += size
	return nil
}

func (decoder *EbpfDecoder) DecodeString(str *string, size int) error {
	offset := decoder.cursor
	bufferLen := len(decoder.buffer[offset:])
	if bufferLen < size {
		return ErrBufferTooShort
	}
	*str = string(decoder.buffer[offset : offset+size])
	decoder.cursor += size
	return nil
}

// DecodeIntArray translate from the decoder buffer, starting from the decoder cursor, to msg, size * 4 bytes (in order to get int32).
func (decoder *EbpfDecoder) DecodeIntArray(msg []int32, size int) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < size*4 {
		return ErrBufferTooShort
	}
	for i := 0; i < size; i++ {
		msg[i] = int32(binary.LittleEndian.Uint32(decoder.buffer[decoder.cursor : decoder.cursor+4]))
		decoder.cursor += 4
	}
	return nil
}

// DecodeUint64Array translate from the decoder buffer, starting from the decoder cursor, to msg, size * 8 bytes (in order to get int64).
func (decoder *EbpfDecoder) DecodeUint64Array(msg *[]uint64) error {
	var arrLen uint16
	err := decoder.DecodeUint16(&arrLen)
	if err != nil {
		return errfmt.Errorf("error reading ulong array number of elements: %v", err)
	}
	for i := 0; i < int(arrLen); i++ {
		var element uint64
		err := decoder.DecodeUint64(&element)
		if err != nil {
			return errfmt.Errorf("can't read element %d uint64 from buffer: %s", i, err)
		}
		*msg = append(*msg, element)
	}
	return nil
}

// DecodeSlimCred translates data from the decoder buffer, starting from the decoder cursor, to SlimCred struct.
func (decoder *EbpfDecoder) DecodeSlimCred(slimCred *SlimCred) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < 80 {
		return ErrBufferTooShort
	}
	slimCred.Uid = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4])
	slimCred.Gid = binary.LittleEndian.Uint32(decoder.buffer[offset+4 : offset+8])
	slimCred.Suid = binary.LittleEndian.Uint32(decoder.buffer[offset+8 : offset+12])
	slimCred.Sgid = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	slimCred.Euid = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	slimCred.Egid = binary.LittleEndian.Uint32(decoder.buffer[offset+20 : offset+24])
	slimCred.Fsuid = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	slimCred.Fsgid = binary.LittleEndian.Uint32(decoder.buffer[offset+28 : offset+32])
	slimCred.UserNamespace = binary.LittleEndian.Uint32(decoder.buffer[offset+32 : offset+36])
	slimCred.SecureBits = binary.LittleEndian.Uint32(decoder.buffer[offset+36 : offset+40])
	slimCred.CapInheritable = binary.LittleEndian.Uint64(decoder.buffer[offset+40 : offset+48])
	slimCred.CapPermitted = binary.LittleEndian.Uint64(decoder.buffer[offset+48 : offset+56])
	slimCred.CapEffective = binary.LittleEndian.Uint64(decoder.buffer[offset+56 : offset+64])
	slimCred.CapBounding = binary.LittleEndian.Uint64(decoder.buffer[offset+64 : offset+72])
	slimCred.CapAmbient = binary.LittleEndian.Uint64(decoder.buffer[offset+72 : offset+80])
	decoder.cursor += int(slimCred.GetSizeBytes())
	return nil
}

// DecodeChunkMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.ChunkMeta struct.
func (decoder *EbpfDecoder) DecodeChunkMeta(chunkMeta *ChunkMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(chunkMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	chunkMeta.BinType = BinType(decoder.buffer[offset])
	chunkMeta.CgroupID = binary.LittleEndian.Uint64(decoder.buffer[offset+1 : offset+9])
	_ = copy(chunkMeta.Metadata[:], decoder.buffer[offset+9:offset+37])
	chunkMeta.Size = int32(binary.LittleEndian.Uint32(decoder.buffer[offset+37 : offset+41]))
	chunkMeta.Off = binary.LittleEndian.Uint64(decoder.buffer[offset+41 : offset+49])
	decoder.cursor += int(chunkMeta.GetSizeBytes())
	return nil
}

// DecodeVfsFileMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.VfsFileMeta struct.
func (decoder *EbpfDecoder) DecodeVfsFileMeta(vfsFileMeta *VfsFileMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(vfsFileMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	vfsFileMeta.DevID = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4])
	vfsFileMeta.Inode = binary.LittleEndian.Uint64(decoder.buffer[offset+4 : offset+12])
	vfsFileMeta.Mode = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	vfsFileMeta.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	decoder.cursor += int(vfsFileMeta.GetSizeBytes())
	return nil
}

// DecodeKernelModuleMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.KernelModuleMeta struct.
func (decoder *EbpfDecoder) DecodeKernelModuleMeta(kernelModuleMeta *KernelModuleMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(kernelModuleMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	kernelModuleMeta.DevID = binary.LittleEndian.Uint32(decoder.buffer[offset : offset+4])
	kernelModuleMeta.Inode = binary.LittleEndian.Uint64(decoder.buffer[offset+4 : offset+12])
	kernelModuleMeta.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+12 : offset+16])
	kernelModuleMeta.Size = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	decoder.cursor += int(kernelModuleMeta.GetSizeBytes())
	return nil
}

// DecodeBpfObjectMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.BpfObjectMeta struct.
func (decoder *EbpfDecoder) DecodeBpfObjectMeta(bpfObjectMeta *BpfObjectMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(bpfObjectMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	_ = copy(bpfObjectMeta.Name[:], decoder.buffer[offset:offset+16])
	bpfObjectMeta.Rand = binary.LittleEndian.Uint32(decoder.buffer[offset+16 : offset+20])
	bpfObjectMeta.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+20 : offset+24])
	bpfObjectMeta.Size = binary.LittleEndian.Uint32(decoder.buffer[offset+24 : offset+28])
	decoder.cursor += int(bpfObjectMeta.GetSizeBytes())
	return nil
}

// DecodeMprotectWriteMeta translates data from the decoder buffer, starting from the decoder cursor, to bufferdecoder.MprotectWriteMeta struct.
func (decoder *EbpfDecoder) DecodeMprotectWriteMeta(mprotectWriteMeta *MprotectWriteMeta) error {
	offset := decoder.cursor
	if len(decoder.buffer[offset:]) < int(mprotectWriteMeta.GetSizeBytes()) {
		return ErrBufferTooShort
	}
	mprotectWriteMeta.Ts = binary.LittleEndian.Uint64(decoder.buffer[offset : offset+8])
	mprotectWriteMeta.Pid = binary.LittleEndian.Uint32(decoder.buffer[offset+8 : offset+12])

	decoder.cursor += int(mprotectWriteMeta.GetSizeBytes())
	return nil
}
