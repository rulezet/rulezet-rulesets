rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_80e6ac924bf1_1798 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"

  strings:
    $s1  = "urn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s2  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"SEo" ascii
    $s3  = "Kl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(functi" ascii
    $s4  = " f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii
    $s5  = "unction f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Wy\";})(),(function f000(){ret" ascii
    $s6  = "n \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(fu" ascii
    $s7  = ")(),(function f000(){return \"Wy\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s8  = "nction f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){ret" ascii
    $s9  = "on f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s10 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}