import "pe"
rule ASPack_v1_02b {
  strings:
    $a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }
    $a1 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}