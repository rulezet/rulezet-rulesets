rule PEiD_01537_PEBundle_v2_0b5___v2_3_ {
  meta:
    description = "[PEBundle v2.0b5 - v2.3]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 01 AD ?? ?? ?? ?? 01 AD }

  condition:
    $a
}