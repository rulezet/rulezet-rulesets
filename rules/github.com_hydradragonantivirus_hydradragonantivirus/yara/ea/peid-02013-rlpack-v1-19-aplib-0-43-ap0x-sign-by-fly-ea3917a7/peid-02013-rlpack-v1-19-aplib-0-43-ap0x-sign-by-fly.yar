rule PEiD_02013_RLPack_V1_19__aPlib_0_43_____ap0x___Sign_by_fly_ {
  meta:
    description = "[RLPack V1.19 (aPlib 0.43) -> ap0x ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 }

  condition:
    $a
}