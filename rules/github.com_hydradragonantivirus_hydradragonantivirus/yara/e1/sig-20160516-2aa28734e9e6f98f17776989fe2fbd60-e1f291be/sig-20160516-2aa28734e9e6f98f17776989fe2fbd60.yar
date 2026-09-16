rule sig_20160516_2aa28734e9e6f98f17776989fe2fbd60 {
  meta:
    description = "datamaliciousorder - file 20160516_2aa28734e9e6f98f17776989fe2fbd60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "487232cd4309652f37900debffefa43331b528959475820ff2d7ca82d518124f"

  strings:
    $s1  = "while (VDxRcyA < fGBpe - (4919 - 4917)) {" fullword ascii
    $s2  = "return sDoEswxW;" fullword ascii
    $s3  = "function UehDbN(tuiyo, fmmd, kemn) {" fullword ascii
    $s4  = "function fqT() {" fullword ascii
    $s5  = "function Gab(joaUEXR) {" fullword ascii
    $s6  = "var QVGv = false;" fullword ascii
    $s7  = "function FRr(jZt, QDp) {" fullword ascii
    $s8  = "var CmuGw = true;" fullword ascii
    $s9  = "function qVC() {" fullword ascii
    $s10 = "if (mfWRc == false) {" fullword ascii
    $s11 = "function JWGs() {" fullword ascii
    $s12 = "return LiMBqOE;" fullword ascii
    $s13 = "return rwXO;" fullword ascii
    $s14 = "switch (\"CbS\") {" fullword ascii
    $s15 = "function UfqGMM(juaqodz) {" fullword ascii
    $s16 = "function qOBiVdS() {" fullword ascii
    $s17 = "function rQl() {" fullword ascii
    $s18 = "var qxHcK = true;" fullword ascii
    $s19 = "return ArioXMpl;" fullword ascii
    $s20 = "return NwDLWcok;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}