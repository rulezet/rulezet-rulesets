rule PEiD_01643_PESpin_1_304____Cyberbob__h__ {
  meta:
    description = "[PESpin 1.304 -> Cyberbob (h)]"
    ep_only     = "false"

  strings:
    $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 }

  condition:
    $a
}