rule sig_20160514_3dc5a3ac0682edb91e991383c4679213 {
  meta:
    description = "datamaliciousorder - file 20160514_3dc5a3ac0682edb91e991383c4679213.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0288e267cd80346d09979c9f3330d959637c954ad5a14782667c95a62306783"

  strings:
    $s1  = "while (HviNSYj < HcDbiSNV - (5504 + 1875 - 7377)) {" fullword ascii
    $s2  = "var MhSKqPB = true;" fullword ascii
    $s3  = "var kbPDkfj = false;" fullword ascii
    $s4  = "function WTqz() {" fullword ascii
    $s5  = "return NmwgTS;" fullword ascii
    $s6  = "return TdoNfTJ;" fullword ascii
    $s7  = "if (KmsIXBZ == true) {" fullword ascii
    $s8  = "function mVdcf() {" fullword ascii
    $s9  = "return LlNECH;" fullword ascii
    $s10 = "function cgpwT() {" fullword ascii
    $s11 = "if (fScd == true) {" fullword ascii
    $s12 = "var zuyavB = false;" fullword ascii
    $s13 = "function nWE() {" fullword ascii
    $s14 = "var NLyd = false;" fullword ascii
    $s15 = "return hrWWPXY;" fullword ascii
    $s16 = "function ZmZsH() {" fullword ascii
    $s17 = "function doMa(cZgFiViI) {" fullword ascii
    $s18 = "var ihWoywkJ = String;" fullword ascii
    $s19 = "function Viu(vrGsrfCk, ZrNguY) {" fullword ascii
    $s20 = "function WDJ(TPpIXa) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}