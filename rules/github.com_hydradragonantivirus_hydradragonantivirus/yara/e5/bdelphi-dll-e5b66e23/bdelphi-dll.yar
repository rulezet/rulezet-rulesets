rule bdelphi_dll {
  meta:
    author      = "PEiD"
    description = "Borland Delphi DLL"
    group       = "11"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00 }

  condition:
    $a0
}