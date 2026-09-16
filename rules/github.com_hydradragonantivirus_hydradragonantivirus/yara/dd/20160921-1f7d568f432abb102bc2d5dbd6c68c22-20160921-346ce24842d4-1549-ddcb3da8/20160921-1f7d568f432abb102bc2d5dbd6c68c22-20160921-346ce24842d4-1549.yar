rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_346ce24842d4_1549 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"

  strings:
    $s1  = "),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){" ascii
    $s2  = "0(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\"" ascii
    $s3  = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s4  = "){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(" ascii
    $s5  = "return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(" ascii
    $s6  = "turn \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s7  = "Sj0\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(funct" ascii
    $s8  = " \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(func" ascii
    $s9  = " f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"K" ascii
    $s10 = "g\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s11 = " f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"G" ascii
    $s12 = "})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}