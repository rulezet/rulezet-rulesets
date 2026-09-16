rule _20160921_1b24f7151bebd3644ff0608076bd2de9_20160921_91424e3b4f10_125 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash2       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"

  strings:
    $s1  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s2  = "nction fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s3  = " \"LGo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s4  = "n \"Ai\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s5  = "on fuck(){return \"Np\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s6  = "n fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s7  = "urn \"ADy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s8  = "rn \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(fu" ascii
    $s9  = "(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"EHo\";}" ascii
    $s10 = "ck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq" ascii
    $s11 = "function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){re" ascii
    $s12 = "k(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Av\";}" ascii
    $s13 = "return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})()" ascii
    $s14 = "n \"IPu\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(fu" ascii
    $s15 = "uck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Xg" ascii
    $s16 = "Pu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function" ascii
    $s17 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s18 = "ck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";" ascii
    $s19 = "nction fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){retu" ascii
    $s20 = ";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}