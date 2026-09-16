rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_1525 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash4       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1  = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return " ascii
    $s2  = "ck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s3  = "eturn \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4  = "rn \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s5  = "urn \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s6  = "rn \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s7  = "(){return \"Hs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s8  = "nction fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){retur" ascii
    $s9  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return" ascii
    $s10 = "ion fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s11 = "nction fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s12 = "(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}