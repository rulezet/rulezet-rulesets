import "elf"
rule MAL_LinkPro_ELF_Rootkit_Golang_Oct25 {
  meta:
    description = "Detects LinkPro rootkit"
    author = "CSIRT Synacktiv, Théo Letailleur"
    date = "2025-10-13"
    reference = "https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis"
    hash = "1368f3a8a8254feea14af7dc928af6847cab8fcceec4f21e0166843a75e81964"
    hash = "d5b2202b7308b25bda8e106552dafb8b6e739ca62287ee33ec77abe4016e698b"
  strings:
    $linkp_mod = "link-pro/link-client" fullword ascii
    $linkp_embed_libld = "resources/libld.so" fullword ascii
    $linkp_embed_lkm = "resources/arp_diag.ko" fullword ascii
    $linkp_ebpf_hide = "hidePrograms" fullword ascii
    $linkp_ebpf_knock = "knock_prog" fullword ascii

    $go_pty = "creack/pty" fullword ascii
    $go_socks = "resocks" fullword ascii

  condition:
    uint32(0) == 0x464c457f and filesize > 5MB and elf.type == elf.ET_EXEC 
    and 2 of ($linkp*) 
    and 1 of ($go*)
}