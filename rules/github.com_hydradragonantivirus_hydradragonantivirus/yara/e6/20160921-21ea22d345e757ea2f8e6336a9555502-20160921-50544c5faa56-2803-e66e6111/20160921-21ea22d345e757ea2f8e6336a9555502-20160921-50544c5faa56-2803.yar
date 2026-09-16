rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_50544c5faa56_2803 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_50544c5faa56c0c9ed1c35075bafc583.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"

  strings:
    $s1 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fuc" ascii
    $s2 = "(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(" ascii
    $s3 = "k(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";" ascii
    $s4 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ar\";})()" ascii
    $s5 = ";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function f" ascii
    $s6 = "s\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s7 = "(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}