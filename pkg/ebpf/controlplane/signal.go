package controlplane

import (
	"github.com/aquasecurity/tracee/pkg/bufferdecoder"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/types/trace"
)

type signal struct {
	id   events.ID
	args []trace.Argument
}

func (sig *signal) Unmarshal(buffer []byte) error {
	ebpfDecoder := bufferdecoder.New(buffer)
	var eventIdUint32 uint32
	err := ebpfDecoder.DecodeUint32(&eventIdUint32)
	if err != nil {
		return errfmt.Errorf("failed to decode signal event ID: %v", err)
	}

	sig.id = events.ID(eventIdUint32)

	var metadata uint32
	err = ebpfDecoder.DecodeUint32(&metadata)
	if err != nil {
		return errfmt.Errorf("failed to decode signal args metadata: %v", err)
	}
	argnum := metadata & 0xff // least significant byte

	eventDefinition := events.Core.GetDefinitionByID(sig.id)
	if eventDefinition.NotValid() {
		return errfmt.Errorf("%d is not a valid event id", sig.id)
	}

	evtFields := eventDefinition.GetFields()
	evtName := eventDefinition.GetName()

	sig.args = make([]trace.Argument, len(evtFields))

	err = ebpfDecoder.DecodeArguments(sig.args, int(argnum), evtFields, evtName, sig.id)
	if err != nil {
		return errfmt.Errorf("failed to decode signal arguments: %v", err)
	}

	return nil
}
