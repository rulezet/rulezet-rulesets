rule PEiD_01536_PEBundle_v0_2___v2_0x_ {
  meta:
    description = "[PEBundle v0.2 - v2.0x]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 6A 04 68 ?? 10 ?? ?? 68 ?? 02 ?? ?? 6A ?? FF 95 }

  condition:
    $a
}