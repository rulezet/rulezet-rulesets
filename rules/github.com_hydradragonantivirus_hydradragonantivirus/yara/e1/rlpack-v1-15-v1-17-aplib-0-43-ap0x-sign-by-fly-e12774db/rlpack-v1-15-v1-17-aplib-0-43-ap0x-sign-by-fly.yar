import "pe"
rule RLPack_V1_15_V1_17__aPlib_0_43_____ap0x_____Sign_By_fly {
  strings:
    $a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

  condition:
    $a0 at pe.entry_point
}