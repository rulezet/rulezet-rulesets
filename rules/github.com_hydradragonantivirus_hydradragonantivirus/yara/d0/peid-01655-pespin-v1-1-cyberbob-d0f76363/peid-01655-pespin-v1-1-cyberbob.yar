rule PEiD_01655_PESpin_V1_1____cyberbob_ {
  meta:
    description = "[PESpin V1.1 -> cyberbob]"
    ep_only     = "true"

  strings:
    $a = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E }

  condition:
    $a
}