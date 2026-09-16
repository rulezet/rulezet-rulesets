rule _20160921_ad0fbcfca87e48302530672c4ceab093_20160921_d35b8ea76f45_4021 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash2       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"
    hash3       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return " ascii
    $s2 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){ret" ascii
    $s3 = "ck(){return \"YQt\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\"" ascii
    $s4 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo0" ascii
    $s5 = "return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})()" ascii
    $s6 = " \"YQt\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}