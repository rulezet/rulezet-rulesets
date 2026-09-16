import "pe"
rule pepack099 {
  meta:
    author      = "PEiD"
    description = "PE Pack 0.99 -> ANAKiN"
    group       = "154"
    function    = "0"

  strings:
    $a0 = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }

  condition:
    $a0 at pe.entry_point
}