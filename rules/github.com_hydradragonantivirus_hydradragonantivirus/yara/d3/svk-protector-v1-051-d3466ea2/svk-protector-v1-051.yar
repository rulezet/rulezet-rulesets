import "pe"
rule SVK_Protector_v1_051 {
  strings:
    $a0 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }

  condition:
    $a0 at pe.entry_point
}