rule _20160921_994c4aa8813658fbb0b792d8aa221e53_20160922_433c067ed379_4001 {
  meta:
    description = "datamaliciousorder - from files 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_7706788d60398ea7d883afb2532d218f.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash2       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash3       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"
    hash4       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "ction f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){retu" ascii
    $s3 = "rn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s4 = "nction f000(){return \"UEg\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000(){retu" ascii
    $s5 = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KDh\";})(),(functi" ascii
    $s6 = "nction f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}