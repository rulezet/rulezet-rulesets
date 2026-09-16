rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_5a42eec12fd0_5156 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"

  strings:
    $s1 = ")(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s2 = "ion fuck(){return \"Wo0\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return " ascii
    $s3 = " fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s4 = "(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s5 = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"YQt\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}