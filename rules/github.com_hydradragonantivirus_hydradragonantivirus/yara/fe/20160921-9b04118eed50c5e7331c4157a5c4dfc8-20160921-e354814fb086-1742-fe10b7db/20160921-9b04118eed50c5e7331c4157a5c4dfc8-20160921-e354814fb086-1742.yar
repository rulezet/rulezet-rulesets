rule _20160921_9b04118eed50c5e7331c4157a5c4dfc8_20160921_e354814fb086_1742 {
  meta:
    description = "datamaliciousorder - from files 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"
    hash2       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1  = "return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"EHo\";})(" ascii
    $s2  = "unction fuck(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii
    $s3  = ";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii
    $s4  = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function f" ascii
    $s5  = "rn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(" ascii
    $s6  = "})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s7  = "on fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s8  = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";})()," ascii
    $s9  = "return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(" ascii
    $s10 = ")(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(" ascii
    $s11 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}