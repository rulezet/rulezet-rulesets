rule sig_20160802_6add0c5922b2d28c5a1c004643b2f441 {
  meta:
    description = "datamaliciousorder - file 20160802_6add0c5922b2d28c5a1c004643b2f441.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6d62aafcb836332d86fb02858bdf52ee1d758e54c16c3798c18e9701521e230"

  strings:
    $s1  = "function lasabtel8() {" fullword ascii
    $s2  = "function jykjunhywxa8() {" fullword ascii
    $s3  = "return oznydegr4;" fullword ascii
    $s4  = "return ikbirfu0;" fullword ascii
    $s5  = "function afbysosn1() {" fullword ascii
    $s6  = "return yjvingevuki7;" fullword ascii
    $s7  = "return ghiweston6;" fullword ascii
    $s8  = "function olyzy4() {" fullword ascii
    $s9  = "function dwycidfybxe2() {" fullword ascii
    $s10 = "function dovizjikhu6() {" fullword ascii
    $s11 = "function uruzind2() {" fullword ascii
    $s12 = "function idedulukdi1() {" fullword ascii
    $s13 = "return fwydlyxo6;" fullword ascii
    $s14 = "function salasas2() {" fullword ascii
    $s15 = "return fotnir4;" fullword ascii
    $s16 = "function ogymalpu0() {" fullword ascii
    $s17 = "return wujyvpo2;" fullword ascii
    $s18 = "function itexpusemi9() {" fullword ascii
    $s19 = "function yhevkej9() {" fullword ascii
    $s20 = "function acyckumw8() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}