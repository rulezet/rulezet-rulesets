rule sig_20160514_ad673cf0755a8a95c07914836a686fca {
  meta:
    description = "datamaliciousorder - file 20160514_ad673cf0755a8a95c07914836a686fca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f6d7fb891a34f674813dd331ad63e7b7783c596fb40ae4d7036214003ca8021"

  strings:
    $s1  = "while (ZwGQ < OSqdENx - (2811 + 2473 - 5282)) {" fullword ascii
    $s2  = "function uEkxmq(cLOGfAfT, sLWS) {" fullword ascii
    $s3  = "return wnjDf;" fullword ascii
    $s4  = "function YcmMOv() {" fullword ascii
    $s5  = "switch (TUOHo) {" fullword ascii
    $s6  = "var ioPBnPUS = String;" fullword ascii
    $s7  = "var cgkkvSi = false;" fullword ascii
    $s8  = "function SLb(upUXGMnr) {" fullword ascii
    $s9  = "var ZhWur = false;" fullword ascii
    $s10 = "return AcvDurF;" fullword ascii
    $s11 = "function zOA() {" fullword ascii
    $s12 = "return fiLfz;" fullword ascii
    $s13 = "function fUU(tuiyo, fmmd, kemn) {" fullword ascii
    $s14 = "return NWaUr;" fullword ascii
    $s15 = "return blyFTOID;" fullword ascii
    $s16 = "var quroBb = false;" fullword ascii
    $s17 = "return CVCuU;" fullword ascii
    $s18 = "function rqybDVG() {" fullword ascii
    $s19 = "if (tfAiO === false) {" fullword ascii
    $s20 = "if (quroBb === false) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}