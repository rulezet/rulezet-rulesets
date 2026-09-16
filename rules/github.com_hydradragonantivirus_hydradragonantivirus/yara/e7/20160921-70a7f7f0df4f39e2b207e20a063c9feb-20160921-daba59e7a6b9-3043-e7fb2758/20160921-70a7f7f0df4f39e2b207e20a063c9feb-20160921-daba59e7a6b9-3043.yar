rule _20160921_70a7f7f0df4f39e2b207e20a063c9feb_20160921_daba59e7a6b9_3043 {
  meta:
    description = "datamaliciousorder - from files 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = "){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})" ascii
    $s2 = "return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Wb\";})()" ascii
    $s3 = "function f000(){return \"MBb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f000(){re" ascii
    $s4 = "TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"RVb\";})(),(funct" ascii
    $s5 = "g\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(functio" ascii
    $s6 = "})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii
    $s7 = " \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}