import "pe"
rule FSG_v2_0____bart_xt {
  strings:
    $a0 = { 87 25 ?? ?? ?? 00 61 94 55 A4 B6 80 FF 13 }

  condition:
    $a0 at pe.entry_point
}