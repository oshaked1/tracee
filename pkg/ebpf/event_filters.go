package ebpf

import (
	"maps"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/logger"
)

type eventFilterHandler func(eventFilters map[string]filters.Filter[*filters.StringFilter], bpfModule *bpf.Module) error

var eventFilterHandlers = map[events.ID]eventFilterHandler{
	events.StackTrace: populateMapsStackTrace,
}

// populateEventFilterMaps populates maps with data from special event filters
func (t *Tracee) populateEventFilterMaps() error {
	// Iterate through registerd event filter handlers
	for eventID, handler := range eventFilterHandlers {
		// Make sure this event is selected
		if _, err := t.eventsDependencies.GetEvent(eventID); err != nil {
			continue
		}

		// Construct filters for this event
		eventFilters := make(map[string]filters.Filter[*filters.StringFilter])
		for it := t.policyManager.CreateAllIterator(); it.HasNext(); {
			p := it.Next()
			f := p.DataFilter.GetEventFilters(eventID)
			if len(f) == 0 {
				continue
			}
			maps.Copy(eventFilters, f)
		}
		if len(eventFilters) == 0 {
			continue
		}

		// Call handler
		err := handler(eventFilters, t.bpfModule)
		if err != nil {
			logger.Errorw("Failed to handle event filters", "event", events.Core.GetDefinitionByID(eventID).GetName(), "error", err)
			err = t.eventsDependencies.RemoveEvent(eventID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func populateMapsStackTrace(eventFilters map[string]filters.Filter[*filters.StringFilter], bpfModule *bpf.Module) error {
	// Get events to produce stack traces for
	eventsFilter, ok := eventFilters["events"].(*filters.StringFilter)
	if !ok {
		return nil
	}
	selectedEvents := eventsFilter.Equal()

	// Check if "all" was specified
	all := false
	for _, event := range selectedEvents {
		if event == "all" {
			all = true
			break
		}
	}
	if all {
		selectedEvents = make([]string, 0, events.MaxCommonID)
		for id := range events.MaxCommonID {
			d := events.Core.GetDefinitionByID(id)
			if d.GetID() != events.Undefined {
				selectedEvents = append(selectedEvents, d.GetName())
			}
		}
	}

	logger.Debugw("stack traces are enabled", "selected events", selectedEvents)

	// Update selected events map
	eventsMap, err := bpfModule.GetMap("su_enabled_evts")
	if err != nil {
		return errfmt.Errorf("could not get BPF map 'su_enabled_evts': %v", err)
	}
	for _, event := range selectedEvents {
		eventID, found := events.Core.GetDefinitionIDByName(event)
		if !found {
			return errfmt.Errorf("invalid event %s", event)
		}
		val := uint32(1)
		if err = eventsMap.Update(unsafe.Pointer(&eventID), unsafe.Pointer(&val)); err != nil {
			return errfmt.Errorf("failed updating stack unwind events map: %v", err)
		}
	}

	return nil
}
