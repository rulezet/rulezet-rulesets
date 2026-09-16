rule _20160921_164a257da283d5c859dcaffb21bf752c_20160921_56567a449e5a_71 {
  meta:
    description = "datamaliciousorder - from files 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash2       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash3       = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash4       = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"

  strings:
    $s1  = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Py\";})()" ascii
    $s2  = ")(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s3  = "(){return \"Ve\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})" ascii
    $s4  = "on fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5  = "n\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii
    $s6  = "unction fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s7  = "ck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"PDf" ascii
    $s8  = "n \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s9  = "eturn \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0\";})(" ascii
    $s10 = " fuck(){return \"Vf\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MO" ascii
    $s11 = "tion fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s12 = " \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s13 = "ction fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retur" ascii
    $s14 = "unction fuck(){return \"Ve\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){ret" ascii
    $s15 = "return \"ZLd\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(" ascii
    $s16 = "Pu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s17 = "on fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s18 = ";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZVi\";})(),(function fu" ascii
    $s19 = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s20 = "return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}