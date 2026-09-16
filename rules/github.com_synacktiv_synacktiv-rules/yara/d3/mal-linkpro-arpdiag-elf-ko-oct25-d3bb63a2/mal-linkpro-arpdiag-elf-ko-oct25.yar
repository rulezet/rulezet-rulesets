import "elf"
rule MAL_LinkPro_arpdiag_ELF_KO_Oct25 {
  meta:
    description = "Detects LinkPro LKM module"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "9fc55dd37ec38990bb27ea2bc18dff0bb2d16ad7aa562ab35a6b63453c397075"
  strings:
    $hook_udp6 = "hook_udp6_seq_show" fullword ascii
    $hook_udp4 = "hook_udp4_seq_show" fullword ascii
    $hook_tcp6 = "hook_tcp6_seq_show" fullword ascii
    $hook_tcp4 = "hook_tcp4_seq_show" fullword ascii
    $ftrace = "ftrace_thunk" fullword ascii
    $hide_entry = "hide_port_init" fullword ascii
    $hide_exit = "hide_port_exit" fullword ascii
  condition:
    uint32(0) == 0x464c457f and filesize < 2MB and elf.type == elf.ET_REL
    and $ftrace
    and 2 of ($hook*) 
    and 1 of ($hide*)
}