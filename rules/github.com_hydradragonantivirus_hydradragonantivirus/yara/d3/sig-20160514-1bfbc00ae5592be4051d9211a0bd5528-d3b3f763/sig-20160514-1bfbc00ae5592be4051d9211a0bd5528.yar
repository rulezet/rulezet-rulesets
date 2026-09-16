rule sig_20160514_1bfbc00ae5592be4051d9211a0bd5528 {
  meta:
    description = "datamaliciousorder - file 20160514_1bfbc00ae5592be4051d9211a0bd5528.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f02d8353768fef69f71448f1509cf3df2fa4f6a17033a06fed34b615e53cc18"

  strings:
    $s1  = "while (sdxKxCTs < AICyAxG - (9245 + 1315 - 10558)) {" fullword ascii
    $s2  = "function IRcuo() {" fullword ascii
    $s3  = "function XmJY() {" fullword ascii
    $s4  = "return LMiUbVb;" fullword ascii
    $s5  = "return OUfoeVe;" fullword ascii
    $s6  = "function wXzAGn() {" fullword ascii
    $s7  = "return CzOg;" fullword ascii
    $s8  = "function gsgP(dfegg) {" fullword ascii
    $s9  = "return XQabpJ;" fullword ascii
    $s10 = "if (!kEmp) {" fullword ascii
    $s11 = "var Lvbv = JATO[XFjAGt];" fullword ascii
    $s12 = "function DmX() {" fullword ascii
    $s13 = "function MqbtUhn() {" fullword ascii
    $s14 = "var kEmp = 0;" fullword ascii
    $s15 = "function kWhY() {" fullword ascii
    $s16 = "return ucKOsMAe;" fullword ascii
    $s17 = "return WDAcHF;" fullword ascii
    $s18 = "return njReYI;" fullword ascii
    $s19 = "function yMwGc() {" fullword ascii
    $s20 = "var qNMeaeR = true;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}