import "pe"
rule AHPack_V0_1____FEUERRADER_____Sign_By_fly {
  strings:
    $a0 = { 60 68 54 ?? ?? 00 B8 48 ?? ?? 00 FF 10 68 B3 ?? ?? 00 50 B8 44 ?? ?? 00 FF 10 68 00 }

  condition:
    $a0 at pe.entry_point
}