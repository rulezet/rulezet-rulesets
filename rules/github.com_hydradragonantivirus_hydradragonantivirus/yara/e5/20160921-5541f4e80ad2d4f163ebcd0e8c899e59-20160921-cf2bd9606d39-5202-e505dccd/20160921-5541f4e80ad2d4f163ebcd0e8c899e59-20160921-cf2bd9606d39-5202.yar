rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_cf2bd9606d39_5202 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = "return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s2 = "function f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s3 = "00(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\"" ascii
    $s4 = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f00" ascii
    $s5 = "nction f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}