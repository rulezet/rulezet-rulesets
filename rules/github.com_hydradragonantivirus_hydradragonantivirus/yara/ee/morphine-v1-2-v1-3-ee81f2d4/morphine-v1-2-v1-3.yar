import "pe"
rule Morphine_v1_2___v1_3 {
  strings:
    $a0 = { FF 25 34 ?? 5A 00 8B C0 FF 25 38 ?? 5A 00 8B C0 }

  condition:
    $a0 at pe.entry_point
}