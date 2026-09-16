rule _20160921_14f99bec2c2ed0c000bf0acbf6c2260c_20160921_3e524aa8d0a1_2730 {
  meta:
    description = "datamaliciousorder - from files 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash2       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash3       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash4       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"
    hash5       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "tion f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return" ascii
    $s2 = "nction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){retur" ascii
    $s3 = "(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){r" ascii
    $s4 = "eturn \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()," ascii
    $s5 = "(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";}" ascii
    $s6 = " \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(funct" ascii
    $s7 = "{return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}