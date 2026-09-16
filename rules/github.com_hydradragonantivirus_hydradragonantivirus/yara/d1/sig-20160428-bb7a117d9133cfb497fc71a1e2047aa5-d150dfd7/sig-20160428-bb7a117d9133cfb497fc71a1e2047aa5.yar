rule sig_20160428_bb7a117d9133cfb497fc71a1e2047aa5 {
  meta:
    description = "datamaliciousorder - file 20160428_bb7a117d9133cfb497fc71a1e2047aa5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f012c178668d2bf7eb0729e84ee86796b2a36908e5744897c72a0c2fb8c4c1af"

  strings:
    $s1  = "while (oNNF < QCMFoxBl - (2043, 3495, 2776, 4391, 2)) {" fullword ascii
    $s2  = "return rHWBPdR + ciSDK + QaWFP + lzcR + spGSy + jfoLV;" fullword ascii
    $s3  = "if (3 == false) {" fullword ascii
    $s4  = "if (3 == true) {" fullword ascii
    $s5  = "if (5 === true) {" fullword ascii
    $s6  = "if (2 == false) {" fullword ascii
    $s7  = "lfdd[aLBlfMO(\"026006061024\")](lgldr, kfkm, false);" fullword ascii
    $s8  = "function aLBlfMO(kInAnyTW) {" fullword ascii
    $s9  = "function NWiMQU(AOIQYX, cfbsZMf) {" fullword ascii
    $s10 = "qJhhkCqM[aLBlfMO(\"026006061024\")](BpLmjc, TVzR, false);" fullword ascii
    $s11 = "function wytA(mnznu, oHiK, FXVBn) {" fullword ascii
    $s12 = "return OFJYWxO[Yeil];" fullword ascii
    $s13 = "var BapMD = false;" fullword ascii
    $s14 = "if (ZyZbIQ === false) {" fullword ascii
    $s15 = "function Iro(dldd, lfdff) {" fullword ascii
    $s16 = "return ebcWaQQj;" fullword ascii
    $s17 = "function iuQrjz(eqj) {" fullword ascii
    $s18 = "if (pDsYH === true) {" fullword ascii
    $s19 = "return qEPO;" fullword ascii
    $s20 = "return iIxhEVW;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}