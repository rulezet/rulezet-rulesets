rule PEiD_01058_Microsoft_Visual_C_5_0_ {
  meta:
    description = "[Microsoft Visual C 5.0]"
    ep_only     = "false"

  strings:
    $a = { 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57 }

  condition:
    $a
}