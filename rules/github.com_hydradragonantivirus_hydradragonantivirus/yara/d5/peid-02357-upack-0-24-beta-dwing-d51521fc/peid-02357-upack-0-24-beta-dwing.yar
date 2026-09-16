rule PEiD_02357_Upack_0_24_beta____Dwing_ {
  meta:
    description = "[Upack 0.24 beta -> Dwing]"
    ep_only     = "true"

  strings:
    $a = { BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 }

  condition:
    $a
}