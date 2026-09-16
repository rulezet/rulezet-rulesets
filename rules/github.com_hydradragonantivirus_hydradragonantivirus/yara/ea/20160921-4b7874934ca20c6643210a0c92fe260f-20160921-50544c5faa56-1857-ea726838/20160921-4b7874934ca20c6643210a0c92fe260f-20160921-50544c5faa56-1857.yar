rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_50544c5faa56_1857 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_50544c5faa56c0c9ed1c35075bafc583.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"

  strings:
    $s1  = "on fuck(){return \"Cd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"I" ascii
    $s2  = "})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(function fu" ascii
    $s3  = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s4  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s5  = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){retur" ascii
    $s6  = "n \"DAa\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s7  = "rn \"USf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s8  = "\"OQr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(functi" ascii
    $s9  = "){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(" ascii
    $s10 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}