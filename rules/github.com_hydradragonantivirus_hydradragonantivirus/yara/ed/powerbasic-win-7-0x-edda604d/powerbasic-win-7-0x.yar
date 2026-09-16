import "pe"
rule PowerBASIC_Win_7_0x {
  strings:
    $a0 = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 0F 85 DB 00 00 00 }

  condition:
    $a0 at pe.entry_point
}