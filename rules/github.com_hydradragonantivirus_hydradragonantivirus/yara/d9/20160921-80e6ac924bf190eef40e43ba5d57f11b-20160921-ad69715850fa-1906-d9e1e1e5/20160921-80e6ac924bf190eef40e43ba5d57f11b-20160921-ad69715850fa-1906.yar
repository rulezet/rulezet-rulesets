rule _20160921_80e6ac924bf190eef40e43ba5d57f11b_20160921_ad69715850fa_1906 {
  meta:
    description = "datamaliciousorder - from files 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1  = ";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f00" ascii
    $s2  = " \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(fun" ascii
    $s3  = "urn \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(f" ascii
    $s4  = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"RLk\";})(),(function f0" ascii
    $s5  = " f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Mc" ascii
    $s6  = "(function f000(){return \"Vu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii
    $s7  = "urn \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"KDh\";})(),(" ascii
    $s8  = "ion f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"" ascii
    $s9  = "on f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s10 = "(),(function f000(){return \"Lp\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}