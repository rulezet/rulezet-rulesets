rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_e59567324a54_4507 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})(),(fun" ascii
    $s3 = "(),(function f000(){return \"IPu\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s4 = "function f000(){return \"Oe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s5 = "0(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}