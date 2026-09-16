rule _20160921_4b85b9629682d9cbd379b3404bd09eb1_20160921_64f93de6a09e_386 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash2       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash3       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash4       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash5       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash6       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"

  strings:
    $s1  = "0(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\"" ascii
    $s2  = "Ux\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function" ascii
    $s3  = ";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s4  = "GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(functi" ascii
    $s5  = "{return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})()," ascii
    $s6  = "Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s7  = "){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})" ascii
    $s8  = "{return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})" ascii
    $s9  = "),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii
    $s10 = "t\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s11 = ")(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000" ascii
    $s12 = "\"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(functi" ascii
    $s13 = "ction f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s14 = "(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})" ascii
    $s15 = "n f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s16 = "ion f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s17 = "\"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(funct" ascii
    $s18 = "000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl" ascii
    $s19 = "{return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"RVb\";})(" ascii
    $s20 = "return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}