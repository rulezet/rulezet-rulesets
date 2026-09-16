rule PEiD_01044_Microsoft_C____1990_1992__ {
  meta:
    description = "[Microsoft C++ (1990/1992)]"
    ep_only     = "true"

  strings:
    $a = { B8 00 30 CD 21 3C 03 73 ?? 0E 1F BA ?? ?? B4 09 CD 21 06 33 C0 50 CB }

  condition:
    $a
}