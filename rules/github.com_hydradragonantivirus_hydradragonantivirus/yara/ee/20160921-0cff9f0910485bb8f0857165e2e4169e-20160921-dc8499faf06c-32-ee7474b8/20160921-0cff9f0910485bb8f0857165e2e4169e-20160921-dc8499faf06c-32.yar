rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_dc8499faf06c_32 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash3       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1  = "0(){return \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\"" ascii
    $s2  = "0(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"PTs\"" ascii
    $s3  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"KDh\";})(),(f" ascii
    $s4  = "urn \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"DNa\";})(),(f" ascii
    $s5  = ";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TKl\";})(),(function f" ascii
    $s6  = "{return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";}" ascii
    $s7  = "on f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s8  = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s9  = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s10 = "tion f000(){return \"Yv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"DNa\";})(),(function f000(){return" ascii
    $s11 = "Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s12 = "),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(" ascii
    $s13 = "{return \"SEo\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DNa\";})" ascii
    $s14 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000()" ascii
    $s15 = "ion f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s16 = " f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"R" ascii
    $s17 = "ction f000(){return \"Vj\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){retur" ascii
    $s18 = "000(){return \"DNa\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Zj" ascii
    $s19 = "\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s20 = " \"Qz\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}