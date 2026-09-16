rule sig_20160427_b49241beb057d87cfa655d96823f0213 {
  meta:
    description = "datamaliciousorder - file 20160427_b49241beb057d87cfa655d96823f0213.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac4d1c48f4bb05cc19eaec4612648d1e231e66ff376dd7f1e102017915789aad"

  strings:
    $s1  = "while (PKKcNYu < saaEG - (5632, 7071, 6430, 9522, 5998, 1338, 2)) {" fullword ascii
    $s2  = "return Vp + JPUE;" fullword ascii
    $s3  = "switch (\"1\") {" fullword ascii
    $s4  = "switch (\"0\") {" fullword ascii
    $s5  = "if (4 === false) {" fullword ascii
    $s6  = "if (1 === false) {" fullword ascii
    $s7  = "if (2 === true) {" fullword ascii
    $s8  = "if (7 == false) {" fullword ascii
    $s9  = "if (2 == true) {" fullword ascii
    $s10 = "if (4 == false) {" fullword ascii
    $s11 = "function MODcdA(gMfgD, jEFHZ, iKOCsH) {" fullword ascii
    $s12 = "var XqrGV = true;" fullword ascii
    $s13 = "function sOzB(iwUfBHcu, zwsT) {" fullword ascii
    $s14 = "return VxVYYz;" fullword ascii
    $s15 = "var rjhlLCl = false;" fullword ascii
    $s16 = "return lj;" fullword ascii
    $s17 = "var hPVkWwa = false;" fullword ascii
    $s18 = "if (wCU == true) {" fullword ascii
    $s19 = "var hurn = false;" fullword ascii
    $s20 = "function TlVEQFv() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}