package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aquasecurity/tracee/pkg/events/findings"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/signatures/metrics"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

const ALL_EVENT_ORIGINS = "*"
const EVENT_CONTAINER_ORIGIN = "container"
const EVENT_HOST_ORIGIN = "host"
const ALL_EVENT_TYPES = "*"

type Mode uint8

const (
	ModeRules Mode = iota
	ModeAnalyze
	ModeSingleBinary
)

// Config defines the engine's configurable values
type Config struct {
	Mode                Mode // Engine in pipeline mode, can be ModeRules, ModeAnalyze or ModeSingleBinary
	NoSignatures        bool // Skip signature processing while keeping events loaded (for performance testing)
	UseSequential       bool // Use sequential processing for CPU optimization
	SignatureBufferSize uint
	AvailableSignatures []detect.Signature // All available signatures found in signature directories
	SelectedSignatures  []detect.Signature // Only signatures that should be loaded based on user policies/events
	DataSources         []detect.DataSource
}

// Engine is a signatures-engine that can process events coming from a set of input sources against a set of loaded signatures, and report the signatures' findings
type Engine struct {
	signatures       map[detect.Signature]chan protocol.Event
	signaturesIndex  map[detect.SignatureEventSelector][]detect.Signature
	signaturesMutex  sync.RWMutex
	inputs           EventSources
	output           chan *detect.Finding
	waitGroup        sync.WaitGroup
	config           Config
	stats            metrics.Stats
	dataSources      map[string]map[string]detect.DataSource
	dataSourcesMutex sync.RWMutex
}

// EventSources is a bundle of input sources used to configure the Engine
type EventSources struct {
	Tracee chan protocol.Event
}

func (engine *Engine) Stats() *metrics.Stats {
	return &engine.stats
}

// NewEngine creates a new signatures-engine with the given arguments
// inputs and outputs are given as channels created by the consumer
// Signatures are not loaded at this point, Init must be called to perform config side effects.
func NewEngine(config Config, sources EventSources, output chan *detect.Finding) (*Engine, error) {
	if sources.Tracee == nil || output == nil {
		return nil, errors.New("nil input received")
	}
	engine := Engine{}
	engine.waitGroup = sync.WaitGroup{}

	engine.inputs = sources
	engine.output = output
	engine.config = config

	engine.signaturesMutex.Lock()
	engine.signatures = make(map[detect.Signature]chan protocol.Event)
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
	engine.signaturesMutex.Unlock()

	engine.dataSourcesMutex.Lock()
	engine.dataSources = map[string]map[string]detect.DataSource{}
	engine.dataSourcesMutex.Unlock()

	return &engine, nil
}

// signatureStart is the signature handling business logics.
func signatureStart(signature detect.Signature, c chan protocol.Event, wg *sync.WaitGroup, noSignatures bool) {
	for e := range c {
		if noSignatures {
			continue // Just drain the channel without processing
		}
		if err := signature.OnEvent(e); err != nil {
			meta, _ := signature.GetMetadata()
			logger.Errorw("Handling event by signature " + meta.Name + ": " + err.Error())
		}
	}
	wg.Done()
}

// Init loads and initializes signatures and data sources passed in NewEngine.
// The split allows the loading of additional signatures and data sources between
// NewEngine and Start if needed.
func (engine *Engine) Init() error {
	for _, dataSource := range engine.config.DataSources {
		err := engine.RegisterDataSource(dataSource)
		if err != nil {
			logger.Errorw("Loading signatures data source: " + err.Error())
		}
	}

	// Load only selected signatures instead of all available signatures
	logger.Debugw("Loading signatures", "total_available", len(engine.config.AvailableSignatures), "selected_for_loading", len(engine.config.SelectedSignatures))
	for _, sig := range engine.config.SelectedSignatures {
		_, err := engine.loadSignature(sig)
		if err != nil {
			logger.Errorw("Loading signature: " + err.Error())
		}
	}

	return nil
}

// Start starts processing events and detecting signatures
// it runs continuously until stopped by the done channel
// once done, it cleans all internal resources, which means the engine is not reusable
// note that the input and output channels are created by the consumer and therefore are not closed
func (engine *Engine) Start(ctx context.Context) {
	defer engine.unloadAllSignatures()

	if engine.config.UseSequential {
		logger.Debugw("Starting signature engine in sequential mode for CPU optimization")
	} else {
		logger.Debugw("Starting signature engine in parallel mode")
		// Only start goroutines in parallel mode
		engine.signaturesMutex.RLock()
		for s, c := range engine.signatures {
			engine.waitGroup.Add(1)
			go signatureStart(s, c, &engine.waitGroup, engine.config.NoSignatures)
		}
		engine.signaturesMutex.RUnlock()
	}

	engine.consumeSources(ctx)
}

func (engine *Engine) unloadAllSignatures() {
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	for sig, c := range engine.signatures {
		sig.Close()
		// Only close channel if it exists (parallel mode)
		if c != nil {
			close(c)
		}
		delete(engine.signatures, sig)
	}
	engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
}

// matchHandler is a function that runs when a signature is matched
func (engine *Engine) matchHandler(res *detect.Finding) {
	_ = engine.stats.Detections.Increment()
	engine.output <- res
	// TODO: the feedback here is enabled only in analyze, as it was causing a deadlock in the pipeline
	//       when the engine was blocked on sending a new event to the feedbacking signature.
	//       This is because the engine would eventually block on trying to to send
	//       a new event to the feedbacking signature. This would cause a deadlock
	//       there - propagating back to the engine and pipeline in general.
	// TODO2: Once we integrate the pipeline into analyze mode, we can remove this logic.
	if !(engine.config.Mode == ModeAnalyze) {
		return
		// next section is relevant only for  analyze
	}
	e, err := findings.FindingToEvent(res)
	if err != nil {
		logger.Errorw("Failed to convert finding to event, will not feedback", "err", err)
		return
	}
	prot := e.ToProtocol()
	engine.inputs.Tracee <- prot
}

// checkCompletion is a function that runs at the end of each input source
// closing tracee-rules if no more pending input sources exists
func (engine *Engine) checkCompletion() bool {
	if engine.inputs.Tracee == nil {
		engine.unloadAllSignatures()
		engine.waitGroup.Wait()
		return true
	}
	return false
}

func (engine *Engine) processEvent(event protocol.Event) {
	engine.signaturesMutex.RLock()
	defer engine.signaturesMutex.RUnlock()

	signatureSelector := detect.SignatureEventSelector{
		Source: event.Headers.Selector.Source,
		Name:   event.Headers.Selector.Name,
		Origin: event.Headers.Selector.Origin,
	}
	_ = engine.stats.Events.Increment()

	// Check the selector for every case and partial case

	// Match full selector
	for _, s := range engine.signaturesIndex[signatureSelector] {
		engine.dispatchEvent(s, event)
	}

	// Match partial selector, select for all origins
	partialSigEvtSelector := detect.SignatureEventSelector{
		Source: signatureSelector.Source,
		Name:   signatureSelector.Name,
		Origin: ALL_EVENT_ORIGINS,
	}
	for _, s := range engine.signaturesIndex[partialSigEvtSelector] {
		engine.dispatchEvent(s, event)
	}

	// Match partial selector, select for event names
	partialSigEvtSelector = detect.SignatureEventSelector{
		Source: signatureSelector.Source,
		Name:   ALL_EVENT_TYPES,
		Origin: signatureSelector.Origin,
	}
	for _, s := range engine.signaturesIndex[partialSigEvtSelector] {
		engine.dispatchEvent(s, event)
	}

	// Match partial selector, select for all origins and event names
	partialSigEvtSelector = detect.SignatureEventSelector{
		Source: signatureSelector.Source,
		Name:   ALL_EVENT_TYPES,
		Origin: ALL_EVENT_ORIGINS,
	}
	for _, s := range engine.signaturesIndex[partialSigEvtSelector] {
		engine.dispatchEvent(s, event)
	}
}

// consumeSources starts consuming the input sources
// it runs continuously until stopped by the done channel
func (engine *Engine) consumeSources(ctx context.Context) {
	for {
		select {
		case event, ok := <-engine.inputs.Tracee:
			if !ok {
				// Skip signature signals if NoSignatures is enabled (signatures not initialized)
				if !engine.config.NoSignatures {
					engine.signaturesMutex.RLock()
					for sig := range engine.signatures {
						se, err := sig.GetSelectedEvents()
						if err != nil {
							logger.Errorw("Getting selected events: " + err.Error())
							continue
						}
						for _, sel := range se {
							if sel.Source == "tracee" {
								_ = sig.OnSignal(detect.SignalSourceComplete("tracee"))
								break
							}
						}
					}
					engine.signaturesMutex.RUnlock()
				}
				engine.inputs.Tracee = nil
				if engine.checkCompletion() {
					close(engine.output)
					return
				}

				continue
			}
			engine.processEvent(event)

		case <-ctx.Done():
			goto drain
		}
	}

drain:
	// drain and process all remaining events
	for {
		select {
		case event := <-engine.inputs.Tracee:
			engine.processEvent(event)

		default:
			return
		}
	}
}

func (engine *Engine) dispatchEvent(s detect.Signature, event protocol.Event) {
	if engine.config.UseSequential {
		// Sequential mode: Direct call for maximum CPU efficiency
		if !engine.config.NoSignatures {
			if err := s.OnEvent(event); err != nil {
				meta, _ := s.GetMetadata()
				logger.Errorw("Processing event in signature " + meta.Name + ": " + err.Error())
			}
		}
	} else {
		// Parallel mode: Original channel dispatch
		engine.signatures[s] <- event
	}
}

// TODO: This method seems not to be used, let's confirm inside the team and remove it if not needed
// LoadSignature will call the internal signature loading logic and activate its handling business logics.
// It will return the signature ID as well as error.
func (engine *Engine) LoadSignature(signature detect.Signature) (string, error) {
	id, err := engine.loadSignature(signature)
	if err != nil {
		return id, err
	}

	// Only start goroutine in parallel mode
	if !engine.config.UseSequential {
		engine.signaturesMutex.RLock()
		engine.waitGroup.Add(1)
		go signatureStart(signature, engine.signatures[signature], &engine.waitGroup, engine.config.NoSignatures)
		engine.signaturesMutex.RUnlock()
	}

	metadata, _ := signature.GetMetadata()
	logger.Debugw("Signature loaded at runtime", "signature", metadata.Name, "event", metadata.EventName, "id", metadata.ID)

	return id, nil
}

// loadSignature handles storing a signature in the Engine data structures
// It will return the signature ID as well as error.
func (engine *Engine) loadSignature(signature detect.Signature) (string, error) {
	metadata, err := signature.GetMetadata()
	if err != nil {
		return "", fmt.Errorf("error getting metadata: %w", err)
	}
	selectedEvents, err := signature.GetSelectedEvents()
	if err != nil {
		return "", fmt.Errorf("error getting selected events for signature %s: %w", metadata.Name, err)
	}

	// Check if signature with this ID already exists
	engine.signaturesMutex.RLock()
	for existingSig := range engine.signatures {
		existingMetadata, _ := existingSig.GetMetadata()
		if existingMetadata.ID == metadata.ID {
			engine.signaturesMutex.RUnlock()
			// signature already exists
			return "", fmt.Errorf("failed to store signature: signature \"%s\" already loaded", metadata.Name)
		}
	}
	engine.signaturesMutex.RUnlock()

	signatureCtx := detect.SignatureContext{
		Callback: engine.matchHandler,
		Logger:   logger.Current(),
		GetDataSource: func(namespace, id string) (detect.DataSource, bool) {
			return engine.GetDataSource(namespace, id)
		},
	}

	// Skip signature initialization if NoSignatures is enabled
	if !engine.config.NoSignatures {
		if err := signature.Init(signatureCtx); err != nil {
			// failed to initialize
			return "", fmt.Errorf("error initializing signature %s: %w", metadata.Name, err)
		}
	}

	engine.signaturesMutex.Lock()
	if engine.config.UseSequential {
		// Sequential mode: No channel needed, store nil
		engine.signatures[signature] = nil
	} else {
		// Parallel mode: Create and store channel
		c := make(chan protocol.Event, engine.config.SignatureBufferSize)
		engine.signatures[signature] = c
	}
	engine.signaturesMutex.Unlock()

	// insert in engine.signaturesIndex map
	for _, selectedEvent := range selectedEvents {
		if selectedEvent.Name == "" {
			selectedEvent.Name = ALL_EVENT_TYPES
		}
		if selectedEvent.Origin == "" {
			selectedEvent.Origin = ALL_EVENT_ORIGINS
		}
		if selectedEvent.Source == "" {
			logger.Errorw("Signature " + metadata.Name + " doesn't declare an input source")
		} else {
			engine.signaturesMutex.Lock()
			engine.signaturesIndex[selectedEvent] = append(engine.signaturesIndex[selectedEvent], signature)
			engine.signaturesMutex.Unlock()
		}
	}

	_ = engine.stats.Signatures.Increment()
	return metadata.ID, nil
}

// UnloadSignature will remove from Engine data structures the given signature and stop its handling goroutine
func (engine *Engine) UnloadSignature(signatureId string) error {
	var signature detect.Signature
	engine.signaturesMutex.RLock()
	for sig := range engine.signatures {
		metadata, _ := sig.GetMetadata()
		if metadata.ID == signatureId {
			signature = sig
			break
		}
	}
	engine.signaturesMutex.RUnlock()
	if signature == nil {
		return fmt.Errorf("could not find signature with ID: %v", signatureId)
	}
	selectedEvents, err := signature.GetSelectedEvents()
	if err != nil {
		return fmt.Errorf("failed to unload signature: %w", err)
	}
	engine.signaturesMutex.Lock()
	defer engine.signaturesMutex.Unlock()
	// remove from engine.signatures map
	c, ok := engine.signatures[signature]
	if ok {
		delete(engine.signatures, signature)
		defer func() {
			_ = engine.stats.Signatures.Decrement()
		}()
		defer signature.Close()
		// Only close channel if it exists (parallel mode)
		if c != nil {
			defer close(c)
		}

		metadata, _ := signature.GetMetadata()
		logger.Debugw("Signature unloaded at runtime", "signature", metadata.Name, "event", metadata.EventName, "id", metadata.ID)
	}
	// remove from engine.signaturesIndex map
	for _, selectedEvent := range selectedEvents {
		signatures := engine.signaturesIndex[selectedEvent]
		for i, sig := range signatures {
			metadata, _ := sig.GetMetadata()
			if metadata.ID == signatureId {
				// signature found, remove it
				signatures = append(signatures[:i], signatures[i+1:]...)
				engine.signaturesIndex[selectedEvent] = signatures
				break
			}
		}
	}
	return nil
}

// GetSelectedEvents returns the event selectors that are relevant to the currently loaded signatures
func (engine *Engine) GetSelectedEvents() []detect.SignatureEventSelector {
	res := make([]detect.SignatureEventSelector, 0)
	for k := range engine.signaturesIndex {
		res = append(res, k)
	}
	return res
}

func (engine *Engine) RegisterDataSource(dataSource detect.DataSource) error {
	engine.dataSourcesMutex.Lock()
	defer engine.dataSourcesMutex.Unlock()

	namespace := dataSource.Namespace()
	id := dataSource.ID()

	if _, ok := engine.dataSources[namespace]; !ok {
		engine.dataSources[namespace] = map[string]detect.DataSource{}
	}

	_, exists := engine.dataSources[namespace][id]
	if exists {
		return fmt.Errorf("failed to register data source: data source with name \"%s\" already exists in namespace \"%s\"", id, namespace)
	}
	engine.dataSources[namespace][id] = dataSource
	return nil
}

func (engine *Engine) GetDataSource(namespace string, id string) (detect.DataSource, bool) {
	engine.dataSourcesMutex.RLock()
	defer engine.dataSourcesMutex.RUnlock()

	namespaceCaches, ok := engine.dataSources[namespace]
	if !ok {
		return nil, false
	}

	cache, ok := namespaceCaches[id]

	return cache, ok
}
