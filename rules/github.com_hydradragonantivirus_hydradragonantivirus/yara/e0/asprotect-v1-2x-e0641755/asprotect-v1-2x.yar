import "pe"
rule ASProtect_v1_2x {
  strings:
    $a0 = { 00 00 68 01 ?? ?? ?? C3 AA }

  condition:
    $a0 at pe.entry_point
}