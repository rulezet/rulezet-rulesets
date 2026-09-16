rule _20160921_aaf08d1a708106f9bd09a913767a56e1_20160921_c05dd34a0935_572 {
  meta:
    description = "datamaliciousorder - from files 20160921_aaf08d1a708106f9bd09a913767a56e1.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"
    hash2       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"

  strings:
    $s1  = "function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"TKp\";})(),(function f000(){r" ascii
    $s2  = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qa\";}" ascii
    $s3  = "unction f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s4  = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s5  = " f000(){return \"PTs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"W" ascii
    $s6  = "o\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s7  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"KDh\";})(),(fun" ascii
    $s8  = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){retu" ascii
    $s9  = "return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(" ascii
    $s10 = "eturn \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})()" ascii
    $s11 = ")(),(function f000(){return \"Km\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s12 = "(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";" ascii
    $s13 = "{return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MBb\";})" ascii
    $s14 = "000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\"" ascii
    $s15 = "turn \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})()," ascii
    $s16 = "00(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MJq\"" ascii
    $s17 = "f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"G" ascii
    $s18 = "000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s19 = "n \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s20 = "0(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}