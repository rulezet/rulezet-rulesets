rule sig_20170430_acb2d22a30f0863ca73d845ec66bc85e {
  meta:
    description = "datamaliciousorder - file 20170430_acb2d22a30f0863ca73d845ec66bc85e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cfea8090bbd0b4a01d4f4c7e631eb6c8d29a1bdfdce1b044251c6fe252fe862"

  strings:
    $s1 = "var rima = 10 * 50;" fullword ascii
    $s2 = "function muhter(kjg, lki) {return kjg.split(lki);}" fullword ascii
    $s3 = "function grohot(hunko,b1,b2,b3) {hunko.open(b1, b2, b3);}" fullword ascii
    $s4 = "var uuu = 0;while(uuu<999999) {uuu++;}" fullword ascii
    $s5 = "function fuuu(fuu1, fuu2) {return fuu1.join(fuu2);}" fullword ascii
    $s6 = "function ataaa(ziyter) {eval(ziyter+'');}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}