rule PEiD_01500_PE_Lock_v1_06_ {
  meta:
    description = "[PE Lock v1.06]"
    ep_only     = "true"

  strings:
    $a = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }

  condition:
    $a
}