import "pe"
rule lcc_dll {
  meta:
    author      = "PEiD"
    description = "LCC Win32 DLL -> Jacob Navia"
    group       = "12"
    function    = "0"

  strings:
    $a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1 }

  condition:
    $a0 at pe.entry_point
}