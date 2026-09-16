import "pe"
rule iPBProtect0_1_5Beta__FORGAT_iPB_ {
  meta:
    author      = "PEiD"
    description = "iPBProtect 0.1.5 Beta -> FORGAT/iPB"
    group       = "Auto"
    function    = "0"

  strings:
    $a0 = { 48 4D 4D 4D 2C 20 49 20 57 49 4C 4C 20 53 57 49 54 43 48 20 54 4F 20 48 41 52 44 43 4F 52 45 20 4D 4F 44 45 21 21 21 4D 55 48 41 48 41 48 41 00 00 00 00 00 00 00 00 00 00 00 00 57 ?? ?? 00 64 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 6C ?? ?? 00 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 ?? ?? ?? 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}