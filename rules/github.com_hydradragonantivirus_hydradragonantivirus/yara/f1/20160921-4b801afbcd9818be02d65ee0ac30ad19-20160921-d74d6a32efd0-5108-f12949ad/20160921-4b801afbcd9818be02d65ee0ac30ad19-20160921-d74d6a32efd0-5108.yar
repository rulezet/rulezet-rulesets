rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_d74d6a32efd0_5108 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = "Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function" ascii
    $s2 = "eturn \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})()" ascii
    $s3 = "return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})()" ascii
    $s4 = "f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj" ascii
    $s5 = "eturn \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"QDg\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}