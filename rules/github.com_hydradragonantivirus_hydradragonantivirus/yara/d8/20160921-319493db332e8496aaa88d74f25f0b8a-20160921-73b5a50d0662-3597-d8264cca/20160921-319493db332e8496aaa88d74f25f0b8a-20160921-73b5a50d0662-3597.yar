rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_73b5a50d0662_3597 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash3       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = " f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh" ascii
    $s2 = "\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function " ascii
    $s3 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vj\";" ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s5 = "ion f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s6 = "nction f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}