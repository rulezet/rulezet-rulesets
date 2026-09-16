rule _20160921_37b7533d4596284ad0b05a77fca64e04_20160922_9d6af2734812_4925 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1 = "0(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\"" ascii
    $s2 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";}" ascii
    $s3 = "000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s4 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Yv\";})(),(func" ascii
    $s5 = " \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NBs\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}