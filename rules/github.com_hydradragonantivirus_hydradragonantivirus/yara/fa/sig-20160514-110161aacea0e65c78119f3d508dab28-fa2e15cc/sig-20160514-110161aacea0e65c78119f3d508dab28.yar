rule sig_20160514_110161aacea0e65c78119f3d508dab28 {
  meta:
    description = "datamaliciousorder - file 20160514_110161aacea0e65c78119f3d508dab28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09a3982e035eaf800d31d4e9228f590cfce1da39a5824f1d6b5a8e3f203b2a2d"

  strings:
    $s1  = "while (ocbKbo < ulcl - (6608 - 6606)) {" fullword ascii
    $s2  = "return zJAMieH;" fullword ascii
    $s3  = "function UiocbQj(dfegg) {" fullword ascii
    $s4  = "function CyTFqOO(rxtbqgn) {" fullword ascii
    $s5  = "function gyg() {" fullword ascii
    $s6  = "function PWcG() {" fullword ascii
    $s7  = "return ElqID;" fullword ascii
    $s8  = "return QLQa;" fullword ascii
    $s9  = "return jTqqEae;" fullword ascii
    $s10 = "function nEGHEd() {" fullword ascii
    $s11 = "return abpeqKKj;" fullword ascii
    $s12 = "function nUqKP() {" fullword ascii
    $s13 = "function QxsmKIl(ZjwlrO) {" fullword ascii
    $s14 = "return TJRdfZ;" fullword ascii
    $s15 = "return OUmt;" fullword ascii
    $s16 = "return IAtvA;" fullword ascii
    $s17 = "return UlTmyE;" fullword ascii
    $s18 = "return JaNzxDIt;" fullword ascii
    $s19 = "function ZYvFhZ(uDdaM) {" fullword ascii
    $s20 = "return UeFe;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}