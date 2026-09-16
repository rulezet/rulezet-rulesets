rule Borland_delphi_6 {
  meta:
    author      = "PEiD"
    description = "Borland Delphi 6.0"
    group       = "444"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D }

  condition:
    $a0
}