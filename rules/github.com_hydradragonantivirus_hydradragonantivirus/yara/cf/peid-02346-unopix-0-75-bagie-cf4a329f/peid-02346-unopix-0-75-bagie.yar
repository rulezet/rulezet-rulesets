rule PEiD_02346_UnoPiX_0_75____BaGiE_ {
  meta:
    description = "[UnoPiX 0.75 -> BaGiE]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 07 00 00 00 61 68 ?? ?? 40 00 C3 83 04 24 18 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 61 }

  condition:
    $a
}