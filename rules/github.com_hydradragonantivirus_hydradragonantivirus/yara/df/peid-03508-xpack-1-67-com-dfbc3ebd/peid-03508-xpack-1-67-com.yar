rule PEiD_03508_XPack_1_67__com_ {
  meta:
    description = "[XPack 1.67 [com]"
    ep_only     = "true"

  strings:
    $a = { E9 53 00 FF FD FF FB FF F9 FF BC 03 00 8B E5 4C 4C C3 }

  condition:
    $a
}