rule sig_20160428_aa0dedf4165871ac14163b7a2486c287 {
  meta:
    description = "datamaliciousorder - file 20160428_aa0dedf4165871ac14163b7a2486c287.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1172cef8e2c201d6af8915941fa35ebb2b10b381eebb5806f6495a40086e98d8"

  strings:
    $s1  = "while (jxNSavW < BMBom - (4342, 5953, 1420, 2930, 1086, 2)) {" fullword ascii
    $s2  = "return ATmMLX + pBm + XIAvpO + azgTXZVS + rjTVJN + vyf;" fullword ascii
    $s3  = "if (2 === true) {" fullword ascii
    $s4  = "if (6 == true) {" fullword ascii
    $s5  = "if (1 == false) {" fullword ascii
    $s6  = "if (7 === true) {" fullword ascii
    $s7  = "if (5 == true) {" fullword ascii
    $s8  = "if (1 === true) {" fullword ascii
    $s9  = "if (7 === false) {" fullword ascii
    $s10 = "var LAPLss = false;" fullword ascii
    $s11 = "if (UkETbc === true) {" fullword ascii
    $s12 = "function mtmNE() {" fullword ascii
    $s13 = "var uPoNi = true;" fullword ascii
    $s14 = "function ZyWU(nEPn, buj, iKgGI, uqIMu) {" fullword ascii
    $s15 = "function MmmKBmK(KOc) {" fullword ascii
    $s16 = "var LbrUgT = true;" fullword ascii
    $s17 = "switch (\"lxAh\") {" fullword ascii
    $s18 = "if (ylS == true) {" fullword ascii
    $s19 = "return ufex;" fullword ascii
    $s20 = "return wwTxG;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}