import "pe"
rule ASProtect_v1_23_RC1 {
  strings:
    $a0 = { 68 01 ?? ?? 00 E8 01 00 00 00 C3 C3 }

  condition:
    $a0 at pe.entry_point
}