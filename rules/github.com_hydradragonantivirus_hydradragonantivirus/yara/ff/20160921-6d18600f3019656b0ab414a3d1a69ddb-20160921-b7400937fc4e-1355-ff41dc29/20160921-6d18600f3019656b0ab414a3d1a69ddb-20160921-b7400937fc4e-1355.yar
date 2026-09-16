rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_b7400937fc4e_1355 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"

  strings:
    $s1  = "tion f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return" ascii
    $s2  = "function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s3  = "),(function f000(){return \"Sq\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s4  = "\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"EZu\";})(),(function " ascii
    $s5  = "tion f000(){return \"Tb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"SGs\";})(),(function f000(){return" ascii
    $s6  = "ion f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s7  = "on f000(){return \"Yv\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"" ascii
    $s8  = "unction f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s9  = "00(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sv\"" ascii
    $s10 = "return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um\";})(" ascii
    $s11 = "ion f000(){return \"PTs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s12 = "){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})" ascii
    $s13 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii
    $s14 = "eturn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Oh\";})(),(" ascii
    $s15 = "eturn \"SEo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}