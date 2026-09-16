rule sig_20160514_c7e2ee21c5b6c3285e990d8966565cff {
  meta:
    description = "datamaliciousorder - file 20160514_c7e2ee21c5b6c3285e990d8966565cff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "affca17aab0989b77411b8a1573727af8bbafb3e0e013b60df267ad7fb252aa4"

  strings:
    $s1  = "while (EdLJ < fXPnUH - (6372 + 2211 - 8581)) {" fullword ascii
    $s2  = "var Swan = qNvAem(EdLJ);" fullword ascii
    $s3  = "if (EIaFv === true) {" fullword ascii
    $s4  = "function FLUaS() {" fullword ascii
    $s5  = "function xangdPJ(eCG) {" fullword ascii
    $s6  = "function BOwzIE(SdI) {" fullword ascii
    $s7  = "var ynKHgg = String;" fullword ascii
    $s8  = "function jHqUHId() {" fullword ascii
    $s9  = "Bygouh = true;" fullword ascii
    $s10 = "return PZdd;" fullword ascii
    $s11 = "function aPZC() {" fullword ascii
    $s12 = "function Plw() {" fullword ascii
    $s13 = "function TzE() {" fullword ascii
    $s14 = "return cGsQniyW;" fullword ascii
    $s15 = "function SxtqZ() {" fullword ascii
    $s16 = "return QtnqUb;" fullword ascii
    $s17 = "return VYArneUk[YTqwEv];" fullword ascii
    $s18 = "function CChPc(rfZeFzQ, tlHzd) {" fullword ascii
    $s19 = "function SkBmJ(tuiyo, fmmd, kemn) {" fullword ascii
    $s20 = "function XzJzBN(OnWRq) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}