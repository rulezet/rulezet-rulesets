rule sig_20160513_4c2ea465ffb46202c3f2cad7d5a909dc {
  meta:
    description = "datamaliciousorder - file 20160513_4c2ea465ffb46202c3f2cad7d5a909dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad1761ed8593c9d8d50e6469dc2b91c87495f5f7cfbd32362bf6522c65510f6d"

  strings:
    $s1  = "while (QgIj < tYUrSkXr - (3329 - 3327)) {" fullword ascii
    $s2  = "return xcOraT;" fullword ascii
    $s3  = "function Wgwh() {" fullword ascii
    $s4  = "function gwNNU(LCMhw, kTCHJ) {" fullword ascii
    $s5  = "function BkoD(KYYHjS, xleX) {" fullword ascii
    $s6  = "return dTUTerdJ;" fullword ascii
    $s7  = "return TVWGiV;" fullword ascii
    $s8  = "var SpaY = 66333;" fullword ascii
    $s9  = "function LhSmeDJ(Yxx) {" fullword ascii
    $s10 = "return XCBgc;" fullword ascii
    $s11 = "function SlTgOl(ObroHo) {" fullword ascii
    $s12 = "return XWBxpXsJ;" fullword ascii
    $s13 = "return ssnvjzJv;" fullword ascii
    $s14 = "function NAZDD() {" fullword ascii
    $s15 = "function zJFKzzV(rtwjdld, kdkndmd) {" fullword ascii
    $s16 = "switch (kkOs) {" fullword ascii
    $s17 = "if (WvGoQ === true) {" fullword ascii
    $s18 = "function mWtO() {" fullword ascii
    $s19 = "function GnS() {" fullword ascii
    $s20 = "return EvztOc;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}