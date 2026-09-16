rule sig_20160514_67d32d3a37d4cb6db847f19c470de32e {
  meta:
    description = "datamaliciousorder - file 20160514_67d32d3a37d4cb6db847f19c470de32e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c185b81390c498e7ba9d87adcda06dfdb58b267f9539a4cd69309030573d3a0d"

  strings:
    $s1  = "while (WyptazlG < JiHd - (4539 + 2058 - 6595)) {" fullword ascii
    $s2  = "function dhxqg(daKUvj) {" fullword ascii
    $s3  = "function AiBfiN() {" fullword ascii
    $s4  = "function PVBzV() {" fullword ascii
    $s5  = "return sOyGHnWt;" fullword ascii
    $s6  = "return CmFjABCk;" fullword ascii
    $s7  = "function uJRns() {" fullword ascii
    $s8  = "return kEFkqqfp;" fullword ascii
    $s9  = "function MlyUehW() {" fullword ascii
    $s10 = "function JkhcHu(hOON, Joou) {" fullword ascii
    $s11 = "return pxrAdi;" fullword ascii
    $s12 = "function dqbMB(rjNbyb, VFkfl) {" fullword ascii
    $s13 = "return FrOFNO;" fullword ascii
    $s14 = "return cCrfeDx;" fullword ascii
    $s15 = "function RleEGVf() {" fullword ascii
    $s16 = "return rrzoSOp;" fullword ascii
    $s17 = "return WIODYDMl;" fullword ascii
    $s18 = "function hBRFXt(tuiyo, fmmd, kemn) {" fullword ascii
    $s19 = "aDOz = true;" fullword ascii
    $s20 = "function swiPkF() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}