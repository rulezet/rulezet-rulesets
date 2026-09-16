rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_9dc96613aa4c_4697 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_9dc96613aa4c64f92e4ff218607f50d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"

  strings:
    $s1 = "n\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(functio" ascii
    $s2 = "(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s3 = "\"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(funct" ascii
    $s4 = "fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "ck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}