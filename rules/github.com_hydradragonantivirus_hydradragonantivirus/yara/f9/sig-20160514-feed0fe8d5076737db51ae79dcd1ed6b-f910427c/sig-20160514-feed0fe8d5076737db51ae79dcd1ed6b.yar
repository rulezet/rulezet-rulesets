rule sig_20160514_feed0fe8d5076737db51ae79dcd1ed6b {
  meta:
    description = "datamaliciousorder - file 20160514_feed0fe8d5076737db51ae79dcd1ed6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d96edebf0b1623e8e1cee8f4e1eb00c89fb29a0299eb60052fc198120ee4a680"

  strings:
    $s1  = "while (KmqqEK < pmBEG - (9851 + 1124 - 10973)) {" fullword ascii
    $s2  = "return LtmOKM;" fullword ascii
    $s3  = "return RWQh[yLrxg];" fullword ascii
    $s4  = "function YFoGijv() {" fullword ascii
    $s5  = "return vTLQk;" fullword ascii
    $s6  = "return aiee;" fullword ascii
    $s7  = "return PRMKDyr;" fullword ascii
    $s8  = "function NbgqaN() {" fullword ascii
    $s9  = "function CYgj() {" fullword ascii
    $s10 = "function IBySRu(twk, DJk) {" fullword ascii
    $s11 = "return HkAOvIX;" fullword ascii
    $s12 = "function Wml() {" fullword ascii
    $s13 = "return rHqvGM;" fullword ascii
    $s14 = "function tpM() {" fullword ascii
    $s15 = "function eyQ(cUa, aMed) {" fullword ascii
    $s16 = "return KRFrtu;" fullword ascii
    $s17 = "function DJvK() {" fullword ascii
    $s18 = "return bLoUq;" fullword ascii
    $s19 = "function hhwOVxU() {" fullword ascii
    $s20 = "return arZs;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}