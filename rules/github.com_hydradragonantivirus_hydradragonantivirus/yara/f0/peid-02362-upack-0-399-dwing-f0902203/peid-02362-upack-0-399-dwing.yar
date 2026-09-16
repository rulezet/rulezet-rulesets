rule PEiD_02362_Upack_0_399____Dwing_ {
  meta:
    description = "[Upack 0.399 -> Dwing]"
    ep_only     = "false"

  strings:
    $a = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }

  condition:
    $a
}