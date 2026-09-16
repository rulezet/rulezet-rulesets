import "pe"
rule pklite32_11 {
  meta:
    author      = "PEiD"
    description = "PKLITE32 1.1 -> PKWARE Inc."
    group       = "161"
    function    = "0"

  strings:
    $a0 = { 55 8B EC A1 ?? ?? ?? ?? 85 C0 74 09 B8 01 ?? ?? ?? 5D C2 0C ?? 8B 45 0C 57 56 53 8B 5D 10 }

  condition:
    $a0 at pe.entry_point
}