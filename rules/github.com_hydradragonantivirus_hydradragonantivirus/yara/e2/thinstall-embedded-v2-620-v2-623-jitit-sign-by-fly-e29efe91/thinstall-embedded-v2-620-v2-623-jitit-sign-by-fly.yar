import "pe"
rule Thinstall_Embedded_V2_620_V2_623____Jitit_____Sign_By_fly {
  strings:
    $a0 = { E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 ?? ?? ?? ?? 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00 }

  condition:
    $a0 at pe.entry_point
}