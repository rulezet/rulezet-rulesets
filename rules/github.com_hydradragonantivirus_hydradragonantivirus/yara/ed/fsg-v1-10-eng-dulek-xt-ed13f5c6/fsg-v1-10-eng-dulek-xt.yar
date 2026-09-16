import "pe"
rule FSG_v1_10__Eng_____dulek_xt {
  strings:
    $a0 = { E8 01 00 00 00 ?? ?? E8 ?? 00 00 00 }
    $a1 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}