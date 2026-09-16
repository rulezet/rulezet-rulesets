import "pe"
rule ASDPack_2_0____asd {
  strings:
    $a0 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }

  condition:
    $a0 at pe.entry_point
}