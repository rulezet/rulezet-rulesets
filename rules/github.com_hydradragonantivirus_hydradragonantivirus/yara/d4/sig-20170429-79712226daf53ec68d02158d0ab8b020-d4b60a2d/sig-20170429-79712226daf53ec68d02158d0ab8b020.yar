rule sig_20170429_79712226daf53ec68d02158d0ab8b020 {
  meta:
    description = "datamaliciousorder - file 20170429_79712226daf53ec68d02158d0ab8b020.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f6cb451b7a2f5f7a349d472ad17a5f0f55b8fdd0891b5a84e52b675484d561f"

  strings:
    $s1 = "var rima = 10 * 50;" fullword ascii
    $s2 = "function grohot(hunko,b1,b2,b3) {hunko.open(b1, b2, b3);}" fullword ascii
    $s3 = "function fuuu(fuu1, fuu2) {return fuu1.join(fuu2);}" fullword ascii
    $s4 = "var uuu = 10;while(uuu<999999) {uuu++;}" fullword ascii
    $s5 = "function ataaa(ziyter) {eval(ziyter+'');}" fullword ascii
    $s6 = "function muhter(kjg, lki) {return kjg.split(lki+'');}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}