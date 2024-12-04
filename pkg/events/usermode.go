// Invoked tracee-ebpf events from user mode
//
// This utility can be useful to generate information needed by signatures that
// is not provided by normal events in the kernel.
//
// Because the events in the kernel are invoked by other programs behavior, we
// cannot anticipate which events will be invoked and as a result what
// information will be extracted.
//
// This is critical because tracee-rules is independent, and doesn't have to run
// on the same machine as tracee-ebpf. This means that tracee-rules might lack
// basic information of the operating machine needed for some signatures.
//
// By creating user mode events this information could be intentionally
// collected and passed to tracee-ebpf afterwards.
package events

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/tracee/pkg/containers"
	containersruntime "github.com/aquasecurity/tracee/pkg/containers/runtime"
	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils/environment"
	traceeversion "github.com/aquasecurity/tracee/pkg/version"
	"github.com/aquasecurity/tracee/types/trace"
	psutilcpu "github.com/shirou/gopsutil/v4/cpu"
	psutilhost "github.com/shirou/gopsutil/v4/host"
	psutilmem "github.com/shirou/gopsutil/v4/mem"
)

const InitProcNsDir = "/proc/1/ns"

// InitNamespacesEvent collect the init process namespaces and create event from
// them.
func InitNamespacesEvent() trace.Event {
	initNamespacesDef := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := getInitNamespaceArguments()

	initNamespacesEvent := trace.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee-ebpf",
		EventID:     int(InitNamespaces),
		EventName:   initNamespacesDef.GetName(),
		ArgsNum:     len(initNamespacesArgs),
		Args:        initNamespacesArgs,
	}

	return initNamespacesEvent
}

// TraceeInfoEvent exports data related to Tracee's initialization
func TraceeInfoEvent(bootTime uint64, startTime uint64) trace.Event {
	def := Core.GetDefinitionByID(TraceeInfo)
	fields := def.GetFields()
	args := []trace.Argument{
		{ArgMeta: fields[0], Value: bootTime},
		{ArgMeta: fields[1], Value: startTime},
		{ArgMeta: fields[2], Value: traceeversion.GetVersion()},
	}

	traceeInfoEvent := trace.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee",
		EventID:     int(def.GetID()),
		EventName:   def.GetName(),
		ArgsNum:     len(args),
		Args:        args,
	}

	return traceeInfoEvent
}

// getInitNamespaceArguments fetches the namespaces of the init process and
// parse them into event arguments.
func getInitNamespaceArguments() []trace.Argument {
	initNamespaces := fetchInitNamespaces()
	eventDefinition := Core.GetDefinitionByID(InitNamespaces)
	initNamespacesArgs := make([]trace.Argument, len(eventDefinition.GetFields()))

	fields := eventDefinition.GetFields()

	for i, arg := range initNamespacesArgs {
		arg.ArgMeta = fields[i]
		arg.Value = initNamespaces[arg.Name]
		initNamespacesArgs[i] = arg
	}

	return initNamespacesArgs
}

// fetchInitNamespaces fetches the namespaces values from the /proc/1/ns
// directory
func fetchInitNamespaces() map[string]uint32 {
	var err error
	var namespacesLinks []os.DirEntry

	initNamespacesMap := make(map[string]uint32)
	namespaceValueReg := regexp.MustCompile(":[[[:digit:]]*]")

	namespacesLinks, err = os.ReadDir(InitProcNsDir)
	if err != nil {
		logger.Errorw("fetching init namespaces", "error", err)
	}
	for _, namespaceLink := range namespacesLinks {
		linkString, _ := os.Readlink(filepath.Join(InitProcNsDir, namespaceLink.Name()))
		trim := strings.Trim(namespaceValueReg.FindString(linkString), "[]:")
		namespaceNumber, _ := strconv.ParseUint(trim, 10, 32)
		initNamespacesMap[namespaceLink.Name()] = uint32(namespaceNumber)
	}

	return initNamespacesMap
}

// ExistingContainersEvents returns a list of events for each existing container
func ExistingContainersEvents(cts *containers.Containers, enrichDisabled bool) []trace.Event {
	var events []trace.Event

	def := Core.GetDefinitionByID(ExistingContainer)
	existingContainers := cts.GetContainers()
	for id, info := range existingContainers {
		cgroupId := uint64(id)
		cRuntime := info.Runtime.String()
		containerId := info.Container.ContainerId
		ctime := info.Ctime.UnixNano()
		container := containersruntime.ContainerMetadata{}
		if !enrichDisabled {
			container, _ = cts.EnrichCgroupInfo(cgroupId)
		}
		fields := def.GetFields()
		args := []trace.Argument{
			{ArgMeta: fields[0], Value: cRuntime},
			{ArgMeta: fields[1], Value: containerId},
			{ArgMeta: fields[2], Value: ctime},
			{ArgMeta: fields[3], Value: container.Image},
			{ArgMeta: fields[4], Value: container.ImageDigest},
			{ArgMeta: fields[5], Value: container.Name},
			{ArgMeta: fields[6], Value: container.Pod.Name},
			{ArgMeta: fields[7], Value: container.Pod.Namespace},
			{ArgMeta: fields[8], Value: container.Pod.UID},
			{ArgMeta: fields[9], Value: container.Pod.Sandbox},
		}
		existingContainerEvent := trace.Event{
			Timestamp:   int(time.Now().UnixNano()),
			ProcessName: "tracee-ebpf",
			EventID:     int(ExistingContainer),
			EventName:   def.GetName(),
			ArgsNum:     len(args),
			Args:        args,
		}
		events = append(events, existingContainerEvent)
	}

	return events
}

// SystemInfoEvent collect information of the system and create an event from them
func SystemInfoEvent(osInfo *environment.OSInfo, kConfig *environment.KernelConfig) trace.Event {
	systemInfoDef := Core.GetDefinitionByID(SystemInfo)
	systemInfoArgs := getSystemInfoArguments(&systemInfoDef, osInfo, kConfig)
	SystemInfoEvent := trace.Event{
		Timestamp:   int(time.Now().UnixNano()),
		ProcessName: "tracee-ebpf",
		EventID:     int(SystemInfo),
		EventName:   systemInfoDef.GetName(),
		ArgsNum:     len(systemInfoArgs),
		Args:        systemInfoArgs,
	}
	return SystemInfoEvent
}

func getSystemInfoArguments(systemInfoDef *Definition, osInfo *environment.OSInfo, kConfig *environment.KernelConfig) []trace.Argument {
	hostID, err := psutilhost.HostID()
	if err != nil {
		hostID = ""
	}

	distro := osInfo.GetOSReleaseID().String()
	distroVersion := osInfo.GetOSReleaseFieldValue(environment.OS_VERSION_ID)
	kernelVersion := osInfo.GetOSReleaseFieldValue(environment.OS_KERNEL_RELEASE)
	arch := osInfo.GetOSReleaseFieldValue(environment.OS_ARCH)

	var totalMem uint64 = 0
	if memStat, err := psutilmem.VirtualMemory(); err == nil {
		totalMem = memStat.Total
	}

	numCPUs, _ := psutilcpu.Counts(true)
	wantedKConfig := getWantedKConfig(kConfig)
	hasBtf := environment.OSBTFEnabled()

	var lockdown string
	if lockdownMode, err := environment.Lockdown(); err == nil {
		lockdown = lockdownMode.String()
	}

	ftraceEnabled, _ := environment.FtraceEnabled()

	bootCommandLine := ""
	if data, err := os.ReadFile("/proc/cmdline"); err == nil {
		bootCommandLine = strings.TrimSpace(string(data))
	}

	cpuFlags, _ := getWantedCPUFlags()
	containerRuntimes := detectContainerRuntimes()

	_, err = os.Stat("/etc/kubernetes/kubelet.conf")
	isKubernetesNode := !os.IsNotExist(err)

	cloudProvider := environment.DetectCloudProvider().String()

	fields := systemInfoDef.GetFields()
	args := []trace.Argument{
		{ArgMeta: fields[0], Value: hostID},
		{ArgMeta: fields[1], Value: distro},
		{ArgMeta: fields[2], Value: distroVersion},
		{ArgMeta: fields[3], Value: kernelVersion},
		{ArgMeta: fields[4], Value: arch},
		{ArgMeta: fields[5], Value: totalMem},
		{ArgMeta: fields[6], Value: uint32(numCPUs)},
		{ArgMeta: fields[7], Value: wantedKConfig},
		{ArgMeta: fields[8], Value: hasBtf},
		{ArgMeta: fields[9], Value: lockdown},
		{ArgMeta: fields[10], Value: ftraceEnabled},
		{ArgMeta: fields[11], Value: bootCommandLine},
		{ArgMeta: fields[12], Value: cpuFlags},
		{ArgMeta: fields[13], Value: containerRuntimes},
		{ArgMeta: fields[14], Value: isKubernetesNode},
		{ArgMeta: fields[15], Value: cloudProvider},
	}
	return args
}

func getWantedKConfig(kConfig *environment.KernelConfig) map[string]string {
	wantedConfigs := []environment.KernelConfigOption{
		environment.CONFIG_BPF_SYSCALL,
		environment.CONFIG_HAVE_EBPF_JIT,
		environment.CONFIG_BPF_JIT,
		environment.CONFIG_BPF_JIT_ALWAYS_ON,
		environment.CONFIG_FTRACE_SYSCALLS,
		environment.CONFIG_BPF_KPROBE_OVERRIDE,
		environment.CONFIG_DEBUG_INFO_BTF,
		environment.CONFIG_DEBUG_INFO_BTF_MODULES,
		environment.CONFIG_BPF_LSM,
		environment.CONFIG_BPF_PRELOAD,
		environment.CONFIG_BPF_PRELOAD_UMD,
		environment.CONFIG_LSM,
		environment.CONFIG_CRASH_CORE,
		environment.CONFIG_VMCORE_INFO,
		environment.CONFIG_PROC_KCORE,
		environment.CONFIG_KALLSYMS,
		environment.CONFIG_KALLSYMS_ALL,
		environment.CONFIG_SLAB,
		environment.CONFIG_SLOB,
		environment.CONFIG_SLUB,
		environment.CONFIG_SLUB_CPU_PARTIAL,
		environment.CONFIG_SLUB_TINY,
		environment.CONFIG_SLUB_DEBUG,
		environment.CONFIG_SLUB_DEBUG_ON,
		environment.CONFIG_PAGE_SHIFT,
		environment.CONFIG_ARM64_PAGE_SHIFT,
		environment.CONFIG_X86_5LEVEL,
		environment.CONFIG_PGTABLE_LEVELS,
		environment.CONFIG_MMU,
		environment.CONFIG_NUMA,
		environment.CONFIG_SPARSEMEM,
		environment.CONFIG_FLATMEM,
		environment.CONFIG_SPARSEMEM_EXTREME,
		environment.CONFIG_SPARSEMEM_VMEMMAP,
	}

	config := make(map[string]string)

	for _, wantedConfig := range wantedConfigs {
		value, err := kConfig.GetValueString(wantedConfig)
		if err == nil {
			value = strings.TrimPrefix(value, "\"")
			value = strings.TrimSuffix(value, "\"")
		} else {
			value = kConfig.GetValue(wantedConfig).String()
		}

		config[wantedConfig.String()] = value
	}

	return config
}

// Get a map from each wanted CPU flag to a bitmap of which CPUs on the system have it.
// The bitmap will be split into multiple uint64 if there are more than 64 CPUs on the system.
func getWantedCPUFlags() (map[string][]uint64, error) {
	var wantedFlags []string

	if runtime.GOARCH == "amd64" {
		wantedFlags = []string{
			"smep", "smap", "nx", "ibrs", "ibpb", "stibp", "md_clear", "ssbd",
			"arch_capabilities", "flush_l1d", "umip", "vmx", "svm", "hypervisor",
			"fsgsbase", "arch_perfmon",
		}
	} else if runtime.GOARCH == "arm64" {
		wantedFlags = []string{
			"pan", "ssbs", "bti", "cpuid", "dcpop", "pmu",
		}
	} else {
		wantedFlags = []string{}
	}

	cpuFlags := make(map[string][]uint64)

	cpusInfo, err := psutilcpu.Info()
	if err != nil {
		return cpuFlags, errfmt.WrapError(err)
	}

	// Iterate over wanted flags
	for _, flag := range wantedFlags {
		cpusBitmaps := make([]uint64, len(cpusInfo)/64+1)

		// Iterate over all CPUs
		for cpuNum, cpuInfo := range cpusInfo {
			// If this CPU has the wanted flag, update the bitmaps for this flag
			if slices.Contains(cpuInfo.Flags, flag) {
				cpusBitmaps[cpuNum/64] |= (1 << (cpuNum % 64))
			}
		}

		cpuFlags[flag] = cpusBitmaps
	}

	return cpuFlags, nil
}

func detectContainerRuntimes() []string {
	runtimeSockets := map[string][]string{
		"docker": {
			"/var/run/docker.sock",
		},
		"containerd": {
			"/var/run/containerd/containerd.sock",
		},
		"cri-o": {
			"/var/run/crio/crio.sock",
		},
		"podman": {
			"/var/run/podman/podman.sock",
		},
		"lxd": {
			"/var/lib/lxd/unix.socket",
			"/var/run/lxd.socket",
			"/var/snap/lxd/common/lxd/unix.socket",
		},
	}

	detectedRuntimes := []string{}

	for runtime, sockets := range runtimeSockets {
		for _, socketPath := range sockets {
			if info, err := os.Stat(socketPath); err == nil {
				if info.Mode()&os.ModeSocket != 0 {
					detectedRuntimes = append(detectedRuntimes, runtime)
				}
			}
		}
	}

	return detectedRuntimes
}
