rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_7f829eb25609_4241 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})()," ascii
    $s2 = " \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s3 = " \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s4 = "tion f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}