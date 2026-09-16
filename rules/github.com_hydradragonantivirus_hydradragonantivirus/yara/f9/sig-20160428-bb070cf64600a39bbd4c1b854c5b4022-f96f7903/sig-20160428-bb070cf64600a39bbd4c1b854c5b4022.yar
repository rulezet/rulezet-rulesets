rule sig_20160428_bb070cf64600a39bbd4c1b854c5b4022 {
  meta:
    description = "datamaliciousorder - file 20160428_bb070cf64600a39bbd4c1b854c5b4022.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5427ccb63325c249c60dc6a1b41b56c2849219021e41c0244c4695fab9499141"

  strings:
    $s1  = "while (zvvZXxOu < MTSRD - (7298, 773, 5308, 594, 2443, 6230, 2)) {" fullword ascii
    $s2  = "return JzQp + QjoQ + VTyfBh + yEK + IqaCbf + khbTGRj;" fullword ascii
    $s3  = "if (7 == true) {" fullword ascii
    $s4  = "if (1 == true) {" fullword ascii
    $s5  = "if (7 === true) {" fullword ascii
    $s6  = "return pQg;" fullword ascii
    $s7  = "if (Gcv === true) {" fullword ascii
    $s8  = "var LUiVx = true;" fullword ascii
    $s9  = "function Vyk() {" fullword ascii
    $s10 = "function aeqE(sXmQ) {" fullword ascii
    $s11 = "function yncIZP(dldd, lfdff) {" fullword ascii
    $s12 = "return kic;" fullword ascii
    $s13 = "function LNI() {" fullword ascii
    $s14 = "switch (\"ngWA\") {" fullword ascii
    $s15 = "if (tbwNiB(675) == true) {" fullword ascii
    $s16 = "function ryn(friesR) {" fullword ascii
    $s17 = "return OhYSymis[rWxYFsb];" fullword ascii
    $s18 = "if (sXhDiL === false) {" fullword ascii
    $s19 = "function ypGo() {" fullword ascii
    $s20 = "return dVjHIc;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}