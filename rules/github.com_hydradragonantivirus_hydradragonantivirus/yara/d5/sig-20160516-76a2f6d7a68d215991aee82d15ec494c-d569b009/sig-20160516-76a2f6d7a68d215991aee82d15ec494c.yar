rule sig_20160516_76a2f6d7a68d215991aee82d15ec494c {
  meta:
    description = "datamaliciousorder - file 20160516_76a2f6d7a68d215991aee82d15ec494c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fedc9c16267220673d11900e585f306bcdb3406291e6cf16725936d07eb04d84"

  strings:
    $s1  = "while (JwwvLf < NFFKs - (8347 - 8345)) {" fullword ascii
    $s2  = "return dBFtPZ;" fullword ascii
    $s3  = "return xwVoZK;" fullword ascii
    $s4  = "function jGiU() {" fullword ascii
    $s5  = "function LzFAX(QNet) {" fullword ascii
    $s6  = "function yFOMG() {" fullword ascii
    $s7  = "function uTiqyLq() {" fullword ascii
    $s8  = "return vkoXxWa;" fullword ascii
    $s9  = "return Pxidw;" fullword ascii
    $s10 = "function Xjv(BuYox) {" fullword ascii
    $s11 = "return qlTL;" fullword ascii
    $s12 = "function ZXLi() {" fullword ascii
    $s13 = "function dOyBl() {" fullword ascii
    $s14 = "return TDRPGUIM[BuYox];" fullword ascii
    $s15 = "return GqJlALDQ;" fullword ascii
    $s16 = "function eaK() {" fullword ascii
    $s17 = "function BrqinHi() {" fullword ascii
    $s18 = "function rePHiyp() {" fullword ascii
    $s19 = "return LehPtYg;" fullword ascii
    $s20 = "function bNAa() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}