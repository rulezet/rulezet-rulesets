import "pe"
rule shrinker33 {
  meta:
    author      = "PEiD"
    description = "Shrinker 3.3 -> Blink Inc."
    group       = "172"
    function    = "0"

  strings:
    $a0 = { 83 3D ?? ?? ?? ?? ?? 55 8B EC 56 57 75 65 68 ?? 01 ?? ?? E8 }

  condition:
    $a0 at pe.entry_point
}