rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_319493db332e_1781 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_319493db332e8496aaa88d74f25f0b8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"

  strings:
    $s1  = "ion f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"TKp\";})(),(function f000(){return " ascii
    $s2  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function " ascii
    $s3  = "nction f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s4  = "f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw" ascii
    $s5  = "return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})()," ascii
    $s6  = "turn \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})()" ascii
    $s7  = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){ret" ascii
    $s8  = " \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s9  = ")(),(function f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s10 = "ction f000(){return \"Wh\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Yz\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}