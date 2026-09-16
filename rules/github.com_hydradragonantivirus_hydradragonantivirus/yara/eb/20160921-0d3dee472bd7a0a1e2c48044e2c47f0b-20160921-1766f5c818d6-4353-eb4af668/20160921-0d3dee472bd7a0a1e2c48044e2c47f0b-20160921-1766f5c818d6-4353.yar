rule _20160921_0d3dee472bd7a0a1e2c48044e2c47f0b_20160921_1766f5c818d6_4353 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash2       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash3       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f" ascii
    $s2 = "on f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s3 = "urn \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(" ascii
    $s4 = "eturn \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})()" ascii
    $s5 = "unction f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}