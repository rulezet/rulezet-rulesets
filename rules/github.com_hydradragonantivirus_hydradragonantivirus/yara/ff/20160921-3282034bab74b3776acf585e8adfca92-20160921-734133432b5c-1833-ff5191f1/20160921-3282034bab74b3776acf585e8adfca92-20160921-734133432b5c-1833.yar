rule _20160921_3282034bab74b3776acf585e8adfca92_20160921_734133432b5c_1833 {
  meta:
    description = "datamaliciousorder - from files 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_734133432b5c6f9bde8604a5856b0226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash2       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"

  strings:
    $s1  = "IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s2  = "ck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ve\"" ascii
    $s3  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){r" ascii
    $s4  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){re" ascii
    $s5  = "urn \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"To\";})(),(f" ascii
    $s6  = "Sx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(functi" ascii
    $s7  = "\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function " ascii
    $s8  = "k(){return \"Yk\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s9  = "turn \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s10 = "fuck(){return \"Ve\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}