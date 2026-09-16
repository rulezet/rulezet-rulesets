rule _20160921_4aeb02b393c6ed3fdeadcb6a29499bfc_20160921_73b5a50d0662_5097 {
  meta:
    description = "datamaliciousorder - from files 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash2       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash3       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "eturn \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s2 = "return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})()" ascii
    $s3 = "n f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"M" ascii
    $s4 = "(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii
    $s5 = "nction f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}