import "pe"
rule aspack_101b {
  meta:
    author      = "PEiD"
    description = "ASPack 1.01b -> Alexey Solodovnikov"
    group       = "100"
    function    = "0"

  strings:
    $a0 = { 60 E8 00 00 00 00 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }

  condition:
    $a0 at pe.entry_point
}