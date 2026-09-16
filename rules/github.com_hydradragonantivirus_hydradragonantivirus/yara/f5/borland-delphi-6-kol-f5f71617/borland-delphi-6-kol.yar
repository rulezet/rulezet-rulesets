rule borland_delphi_6_kol {
  meta:
    author      = "PEiD"
    description = "Borland Delphi 6.0 KOL"
    group       = "444"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF A1 ?? 72 40 00 33 D2 E8 ?? ?? FF FF A1 ?? 72 40 00 8B 00 83 C0 14 E8 ?? ?? FF FF E8 ?? ?? FF FF }

  condition:
    $a0
}