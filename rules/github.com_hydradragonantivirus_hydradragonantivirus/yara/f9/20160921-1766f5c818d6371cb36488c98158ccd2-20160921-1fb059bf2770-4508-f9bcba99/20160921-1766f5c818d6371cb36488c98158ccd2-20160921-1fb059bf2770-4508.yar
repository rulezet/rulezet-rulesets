rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_1fb059bf2770_4508 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash3       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash4       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = " f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WI" ascii
    $s2 = "00(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";" ascii
    $s3 = "function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s4 = " \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s5 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}