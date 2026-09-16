import "elf"
rule MAL_LinkPro_Hide_ELF_BPF_Oct25 {
  meta:
    description = "Detects LinkPro Hide eBPF module"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "b8c8f9888a8764df73442ea78393fe12464e160d840c0e7e573f5d9ea226e164"
  strings:
    $hook_getdents = "/syscalls/sys_enter_getdents" fullword ascii
    $hook_getdentsret = "/syscalls/sys_exit_getdents" fullword ascii
    $hook_bpf = "/syscalls/sys_enter_bpf" fullword ascii
    $hook_bpfret = "sys_bpf" fullword ascii
    $str1 = "BPF cmd: %d, start_id: %u" fullword ascii
    $str2 = "HIDING NEXT_ID: %u" fullword ascii
    $str3 = ".tmp~data" fullword ascii

  condition:
    uint32(0) == 0x464c457f and uint16(0x12) == 0x00f7     and elf.type == elf.ET_REL  
    and 2 of ($hook*)
    and 1 of ($str*)
}