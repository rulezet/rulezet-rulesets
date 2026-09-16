rule sig_20160429_b1352e234d0013291bb40f544580d7b9 {
  meta:
    description = "datamaliciousorder - file 20160429_b1352e234d0013291bb40f544580d7b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43d57e3490bf9058ee4ae56ee9e7106664dc68cde0dbdbc158ae8c8a6c1e83b2"

  strings:
    $s1  = "while (Dek < DrPVQJmW - (8354, 9809, 5414, 4259, 60, 5965, 8607, 2144, 1182, 9130, 2)) {" fullword ascii
    $s2  = "return kQEjM + jiEFb + xKwU + xixMbXqt + kGzXfKOK + AkdIPJKd;" fullword ascii
    $s3  = "if (6 === false) {" fullword ascii
    $s4  = "if (5 === true) {" fullword ascii
    $s5  = "if (1 == false) {" fullword ascii
    $s6  = "if (7 == true) {" fullword ascii
    $s7  = "if (1 == true) {" fullword ascii
    $s8  = "if (7 === false) {" fullword ascii
    $s9  = "function myAst(dldd, lfdff) {" fullword ascii
    $s10 = "var XqZqlAr = false;" fullword ascii
    $s11 = "function uNqGnO(sQihYO, RLjGu) {" fullword ascii
    $s12 = "function wIWMP() {" fullword ascii
    $s13 = "switch (228) {" fullword ascii
    $s14 = "function nMToulx() {" fullword ascii
    $s15 = "return VJc;" fullword ascii
    $s16 = "return DDSSn;" fullword ascii
    $s17 = "return zvQoJUMn;" fullword ascii
    $s18 = "function zfsAh(Hgj) {" fullword ascii
    $s19 = "return rVzSmK;" fullword ascii
    $s20 = "switch (\"CotwXg\") {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}