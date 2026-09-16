rule sig_20160428_2d5b7827d0ccd77ad5317f5736329596 {
  meta:
    description = "datamaliciousorder - file 20160428_2d5b7827d0ccd77ad5317f5736329596.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ab035bb24e29c9365af486ccf49c03fceb6d2882763a207b12dd4014f311488"

  strings:
    $s1  = "while (FIzAS < hOTbo - (636, 6548, 5153, 874, 1361, 3613, 332, 1390, 7159, 1564, 418, 9066, 2)) {" fullword ascii
    $s2  = "return LNyJ + BvLmfmkN + csdiHQtH + CuLoBglS + YrCQSXBf + OpR;" fullword ascii
    $s3  = "return biNSMhvX;" fullword ascii
    $s4  = "if (4 === false) {" fullword ascii
    $s5  = "if (1 === false) {" fullword ascii
    $s6  = "if (5 === true) {" fullword ascii
    $s7  = "if (7 == false) {" fullword ascii
    $s8  = "function LGBAP() {" fullword ascii
    $s9  = "function MLs() {" fullword ascii
    $s10 = "function dkcqye(rEhNlg) {" fullword ascii
    $s11 = "return hkT[oIZE];" fullword ascii
    $s12 = "function CWwJhfJ() {" fullword ascii
    $s13 = "return urgd;" fullword ascii
    $s14 = "function Thy() {" fullword ascii
    $s15 = "function CgtsIEM() {" fullword ascii
    $s16 = "var CSCDbWA = true;" fullword ascii
    $s17 = "function kuyiI() {" fullword ascii
    $s18 = "return tJytxlpi;" fullword ascii
    $s19 = "return GbiOh;" fullword ascii
    $s20 = "return TcBIou;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}