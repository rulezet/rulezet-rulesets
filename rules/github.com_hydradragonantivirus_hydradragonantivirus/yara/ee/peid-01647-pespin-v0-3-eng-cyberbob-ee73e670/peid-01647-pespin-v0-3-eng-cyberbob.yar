rule PEiD_01647_PESpin_v0_3__Eng_____cyberbob_ {
  meta:
    description = "[PESpin v0.3 (Eng) -> cyberbob]"
    ep_only     = "true"

  strings:
    $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 }

  condition:
    $a
}