rule _20160921_4ad5ed78dc05b02005f65ab785b9c74a_20160921_a1cbb43a1e22_5095 {
  meta:
    description = "datamaliciousorder - from files 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash2       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"
    hash4       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "urn \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"BMj\";})(),(f" ascii
    $s2 = "unction f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){retu" ascii
    $s3 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Rh\";})(),(func" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(fun" ascii
    $s5 = "f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nv" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}