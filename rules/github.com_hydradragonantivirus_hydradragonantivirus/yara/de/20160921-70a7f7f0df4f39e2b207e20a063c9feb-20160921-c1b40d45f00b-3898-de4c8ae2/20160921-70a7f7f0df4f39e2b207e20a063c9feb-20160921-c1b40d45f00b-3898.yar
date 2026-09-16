rule _20160921_70a7f7f0df4f39e2b207e20a063c9feb_20160921_c1b40d45f00b_3898 {
  meta:
    description = "datamaliciousorder - from files 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash2       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"

  strings:
    $s1 = "eturn \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})()" ascii
    $s2 = "Ux\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"KXg\";})(),(function" ascii
    $s3 = "ction f000(){return \"Vj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"OMd\";})(),(function f000(){retur" ascii
    $s4 = "g\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(function" ascii
    $s5 = "tion f000(){return \"Km\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return" ascii
    $s6 = "eturn \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}