rule sig_20160513_02c2a3760f7c8fe0de08735c3ce04633 {
  meta:
    description = "datamaliciousorder - file 20160513_02c2a3760f7c8fe0de08735c3ce04633.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18c7f5055ff41d85b86272fd47fdcf8691783747856836d794a551b250ca3410"

  strings:
    $s1  = "while (IOuboaTz < RavlAl - (6218 + 2019 - 8235)) {" fullword ascii
    $s2  = "function yIrCS() {" fullword ascii
    $s3  = "return UNSqmBIP;" fullword ascii
    $s4  = "return nvYxiD;" fullword ascii
    $s5  = "function prBU() {" fullword ascii
    $s6  = "return BoyIOva;" fullword ascii
    $s7  = "return FSlBRL;" fullword ascii
    $s8  = "var RluyA = true;" fullword ascii
    $s9  = "function UBQuma(PknQuBZ, qaP) {" fullword ascii
    $s10 = "var cqbxw = true;" fullword ascii
    $s11 = "function fqNw() {" fullword ascii
    $s12 = "return voNHQv;" fullword ascii
    $s13 = "function lSY(rtwjdld, kdkndmd) {" fullword ascii
    $s14 = "function EXfrT(iDSacejs, sPHiEaF) {" fullword ascii
    $s15 = "return FCIw;" fullword ascii
    $s16 = "function Cmik(tuiyo, fmmd, kemn) {" fullword ascii
    $s17 = "function hVt() {" fullword ascii
    $s18 = "function CjtyzfN() {" fullword ascii
    $s19 = "function aJGNUv() {" fullword ascii
    $s20 = "function uklV(MjXvdMW, DDdNaAMf) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}