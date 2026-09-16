rule sig_20160429_c33d22778a9ce3992628e33765ce4259 {
  meta:
    description = "datamaliciousorder - file 20160429_c33d22778a9ce3992628e33765ce4259.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afaf0d4ed8ddeefbcd76e3e462df9b4d92401c9f924e57747c3a787f7dd9c64f"

  strings:
    $s1  = "while (CmJTnjCJ < UtwtemjP - (3380, 7741, 1270, 7145, 9603, 7262, 2)) {" fullword ascii
    $s2  = "if (2 === true) {" fullword ascii
    $s3  = "if (6 == true) {" fullword ascii
    $s4  = "if (6 == false) {" fullword ascii
    $s5  = "if (5 == true) {" fullword ascii
    $s6  = "if (4 === true) {" fullword ascii
    $s7  = "switch (\"JfTuEkcQ\") {" fullword ascii
    $s8  = "function SEGTItB() {" fullword ascii
    $s9  = "return Mrpgsl;" fullword ascii
    $s10 = "var Pxiviw = true;" fullword ascii
    $s11 = "var aMmZ = false;" fullword ascii
    $s12 = "function BSSriAz() {" fullword ascii
    $s13 = "switch (\"mVhyHP\") {" fullword ascii
    $s14 = "function IhtY(FLefJl) {" fullword ascii
    $s15 = "return RYb;" fullword ascii
    $s16 = "var uOuStZ = true;" fullword ascii
    $s17 = "return TfF[0];" fullword ascii
    $s18 = "function qIVn() {" fullword ascii
    $s19 = "if (GhChVIW == true) {" fullword ascii
    $s20 = "return zHziqoj[FLefJl];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}