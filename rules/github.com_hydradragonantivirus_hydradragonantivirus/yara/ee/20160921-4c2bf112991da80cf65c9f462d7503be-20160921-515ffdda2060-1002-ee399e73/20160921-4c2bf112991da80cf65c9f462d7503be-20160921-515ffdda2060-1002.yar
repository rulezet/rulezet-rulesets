rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_1002 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash4       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash5       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1  = ";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fu" ascii
    $s2  = "\"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii
    $s3  = "nction fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s4  = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"" ascii
    $s5  = " \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(func" ascii
    $s6  = "a\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function " ascii
    $s7  = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu" ascii
    $s8  = "turn \"Ar\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s9  = "Ik\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s10 = "rn \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(fu" ascii
    $s11 = " fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Z" ascii
    $s12 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Yk\";})(),(function fuc" ascii
    $s13 = "n fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s14 = "uck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd" ascii
    $s15 = ")(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck" ascii
    $s16 = "function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AJs\";})(),(function fuck(){r" ascii
    $s17 = "fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GN" ascii
    $s18 = "){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IRn\";})" ascii
    $s19 = "ck(){return \"Ai\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MBg" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}