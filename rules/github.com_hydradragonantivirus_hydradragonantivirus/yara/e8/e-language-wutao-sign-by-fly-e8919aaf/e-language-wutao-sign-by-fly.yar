import "pe"
rule E_Language____WuTao_____Sign_By_fly {
  strings:
    $a0 = { E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF }

  condition:
    $a0 at pe.entry_point
}