import "pe"
rule Borland_Pascal_v7_0_for_Windows {
  strings:
    $a0 = { 9A FF FF 00 00 9A FF FF 00 00 55 89 E5 31 C0 9A FF FF 00 00 }

  condition:
    $a0 at pe.entry_point
}