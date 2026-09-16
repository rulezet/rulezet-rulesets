import "elf"
rule MAL_LinkPro_Knock_ELF_BPF_Oct25 {
  meta:
    description = "Detects LinkPro Knock eBPF module"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "364c680f0cab651bb119aa1cd82fefda9384853b1e8f467bcad91c9bdef097d3"
  strings:
    $hook_xdp = "xdp_ingress" fullword ascii
    $hook_tc_egress = "tc_egress" fullword ascii
    $str1 = "[DBG-XDP]" fullword ascii
    $str2 = "[DBG-9999]" fullword ascii
    $str3 = "[TC-MISS]" fullword ascii
    $str4 = "[TC] REWRITE_BACK" fullword ascii
  condition:
    uint32(0) == 0x464c457f and uint16(0x12) == 0x00f7     and elf.type == elf.ET_REL 
    and 1 of ($hook*)
    and 2 of ($str*)
}