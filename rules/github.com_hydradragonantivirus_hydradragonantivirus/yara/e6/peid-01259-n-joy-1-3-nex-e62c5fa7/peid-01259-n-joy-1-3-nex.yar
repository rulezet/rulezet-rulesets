rule PEiD_01259_N_Joy_1_3____NEX_ {
  meta:
    description = "[N-Joy 1.3 -> NEX]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 B8 48 36 40 00 E8 54 EE FF FF 6A 00 68 D8 2B 40 00 6A 0A 6A 00 E8 2C EF FF FF E8 23 E7 FF FF 8D 40 00 }

  condition:
    $a
}