import "elf"
rule MAL_LinkPro_LdPreload_ELF_SO_Oct25 {
  meta:
    description = "Detects LinkPro ld preload module"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "b11a1aa2809708101b0e2067bd40549fac4880522f7086eb15b71bfb322ff5e7"
  strings:
    $hook_getdents = "getdents" fullword ascii
    $hook_open = "open" fullword ascii
    $hook_readdir = "readdir" fullword ascii
    $hook_kill = "kill" fullword ascii
    $linkpro = ".tmp~data" fullword ascii
    $file_net = "/proc/net" fullword ascii
    $file_persist = ".system" fullword ascii
    $file_cron = "sshids" fullword ascii
  condition:
    uint32(0) == 0x464c457f and filesize < 500KB and elf.type == elf.ET_DYN
    and $linkpro
    and 2 of ($hook*)
    and 2 of ($file*)
}