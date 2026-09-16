rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_60c26fdfafa2_4509 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_60c26fdfafa2666b92246aea46e32175.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"

  strings:
    $s1 = "return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "ion f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s3 = " \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(func" ascii
    $s4 = ";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f" ascii
    $s5 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"UEg\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}