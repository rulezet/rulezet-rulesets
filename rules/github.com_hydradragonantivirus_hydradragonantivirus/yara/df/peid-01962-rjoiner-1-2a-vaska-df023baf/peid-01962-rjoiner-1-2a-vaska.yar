rule PEiD_01962_RJoiner_1_2a____Vaska_ {
  meta:
    description = "[RJoiner 1.2a -> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 81 EC 0C 01 00 00 8D 85 F4 FE FF FF 56 50 68 04 01 00 00 FF 15 0C 10 40 00 94 90 94 8D 85 F4 FE FF FF 50 FF 15 08 10 40 00 94 90 94 BE 00 20 40 00 94 90 94 83 3E FF 74 7D 53 57 33 DB 8D 7E 04 94 90 94 53 68 80 00 00 00 6A 02 53 6A 01 68 00 00 00 }

  condition:
    $a
}