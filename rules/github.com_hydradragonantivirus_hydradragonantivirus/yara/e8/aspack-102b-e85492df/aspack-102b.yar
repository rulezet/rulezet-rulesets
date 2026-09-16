import "pe"
rule aspack_102b {
  meta:
    author      = "PEiD"
    description = "ASPack 1.02b -> Alexey Solodovnikov"
    group       = "100"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }

  condition:
    $a0 at pe.entry_point
}