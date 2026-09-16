rule _20160921_0a459915b243d5878c25fef831b72789_20160921_2fddda42e591_4329 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash3       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash4       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1 = "n \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(fu" ascii
    $s2 = "urn \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(" ascii
    $s3 = " f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"R" ascii
    $s4 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000" ascii
    $s5 = "ction f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}