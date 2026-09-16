rule PEiD_00784_FSG_v1_10__Eng_____bart_xt____WinRAR_SFX_ {
  meta:
    description = "[FSG v1.10 (Eng) -> bart/xt -> WinRAR-SFX]"
    ep_only     = "true"

  strings:
    $a = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }

  condition:
    $a
}