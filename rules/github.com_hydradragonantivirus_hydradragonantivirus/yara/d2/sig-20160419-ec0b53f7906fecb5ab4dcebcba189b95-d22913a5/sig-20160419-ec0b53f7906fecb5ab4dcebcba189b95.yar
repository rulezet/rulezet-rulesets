rule sig_20160419_ec0b53f7906fecb5ab4dcebcba189b95 {
  meta:
    description = "datamaliciousorder - file 20160419_ec0b53f7906fecb5ab4dcebcba189b95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d7228f83ebbfa1c16723809e775a19e82db4d21a5f9908f014b804579be7401"

  strings:
    $s1  = "while (JHMXoIIb < jp - (5304, 722, 6294, 6956, 4437, 670, 5734, 2)) {" fullword ascii
    $s2  = "return WScript;" fullword ascii
    $s3  = "NWuS = tuza * FokC;" fullword ascii
    $s4  = "return oedObg + YYUuW + RkSnOHY + HOrhz;" fullword ascii
    $s5  = "function vBuzWd(zalpL, Couq) {" fullword ascii
    $s6  = "switch (\"1\") {" fullword ascii
    $s7  = "switch (\"0\") {" fullword ascii
    $s8  = "if (1 === false) {" fullword ascii
    $s9  = "if (2 === true) {" fullword ascii
    $s10 = "if (2 == false) {" fullword ascii
    $s11 = "if (7 == false) {" fullword ascii
    $s12 = "var dNYjDl = false;" fullword ascii
    $s13 = "if (IaV === false) {" fullword ascii
    $s14 = "if (WNvy === false) {" fullword ascii
    $s15 = "if (dEWOHZj == true) {" fullword ascii
    $s16 = "var zwfAAY = true;" fullword ascii
    $s17 = "var UjwLs = false;" fullword ascii
    $s18 = "function DKZA(qUG, eolWhI, xrqer, pjr) {" fullword ascii
    $s19 = "DKZA(\"0\", false, true, 9425);" fullword ascii
    $s20 = "function FZzGfzC(THgL, JJm, jkJ, WNvy) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}