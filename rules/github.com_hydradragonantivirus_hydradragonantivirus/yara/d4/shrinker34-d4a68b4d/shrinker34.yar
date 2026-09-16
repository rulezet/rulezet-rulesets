import "pe"
rule shrinker34 {
  meta:
    author      = "PEiD"
    description = "Shrinker 3.4 -> Blink Inc."
    group       = "172"
    function    = "0"

  strings:
    $a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? ?? ?? ?? 83 C4 04 8B 75 08 A3 ?? ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }

  condition:
    $a0 at pe.entry_point
}