import "pe"
rule ASPack_v2_001 {
  strings:
    $a0 = { 60 E8 72 05 00 00 EB 4C }

  condition:
    $a0 at pe.entry_point
}