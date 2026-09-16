rule PEiD_01999_RLPack_V1_15_V1_17__aPlib_0_43_____ap0x___Sign_by_fly_ {
  meta:
    description = "[RLPack V1.15-V1.17 (aPlib 0.43) -> ap0x ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

  condition:
    $a
}