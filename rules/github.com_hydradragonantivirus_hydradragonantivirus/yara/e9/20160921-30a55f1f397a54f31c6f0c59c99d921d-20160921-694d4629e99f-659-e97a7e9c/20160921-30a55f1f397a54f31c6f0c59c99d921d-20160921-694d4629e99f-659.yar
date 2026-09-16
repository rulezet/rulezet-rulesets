rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_694d4629e99f_659 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash3       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash4       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"

  strings:
    $s1  = "n \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s2  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s3  = "ck(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s4  = "\"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";})(),(func" ascii
    $s5  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MUs" ascii
    $s6  = " fuck(){return \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IP" ascii
    $s7  = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})()" ascii
    $s8  = "ion fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s9  = "g\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"FJs\";})(),(functio" ascii
    $s10 = "),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){" ascii
    $s11 = " \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s12 = "(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";" ascii
    $s13 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return " ascii
    $s14 = "nction fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s15 = "uck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu" ascii
    $s16 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";})(),(functio" ascii
    $s17 = "uck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\"" ascii
    $s18 = "{return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})" ascii
    $s19 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XCr" ascii
    $s20 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}