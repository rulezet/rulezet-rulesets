rule sig_20170416_defe03abd03bc238f28294c00d6d2a96 {
  meta:
    description = "datamaliciousorder - file 20170416_defe03abd03bc238f28294c00d6d2a96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc26ebcac7f8a7676572c8a4320dc70a23fcf1fbd81504939bdb414b609844a5"

  strings:
    $s1 = "var rima = 500;" fullword ascii
    $s2 = "function ataaa(ziyter) {eval(ziyter);}" fullword ascii
    $s3 = "function muhter(kjg, lki) {return kjg.split(lki);}" fullword ascii
    $s4 = "function grohot(hunko,b1,b2,b3) {hunko.open(b1, b2, b3);}" fullword ascii
    $s5 = "var uuu = 0;while(uuu<999999) {uuu++;}" fullword ascii
    $s6 = "function fuuu(fuu1, fuu2) {return fuu1.join(fuu2);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}