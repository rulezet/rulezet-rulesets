rule _20160921_3bce2f31e98c152d025886ed17309773_20160921_c1184914bc80_4994 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash2       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash4       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(func" ascii
    $s2 = ",(function f000(){return \"ZFe\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){" ascii
    $s3 = " \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s4 = " \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(fu" ascii
    $s5 = "n f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}