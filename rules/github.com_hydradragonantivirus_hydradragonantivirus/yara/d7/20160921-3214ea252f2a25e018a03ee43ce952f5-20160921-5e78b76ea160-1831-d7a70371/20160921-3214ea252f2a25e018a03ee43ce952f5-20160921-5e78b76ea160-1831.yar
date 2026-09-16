rule _20160921_3214ea252f2a25e018a03ee43ce952f5_20160921_5e78b76ea160_1831 {
  meta:
    description = "datamaliciousorder - from files 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash2       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash3       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1  = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Sx" ascii
    $s2  = "turn \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})()" ascii
    $s3  = "\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xw\";})(),(function fu" ascii
    $s4  = "\"ZWu\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GWo\";})(),(func" ascii
    $s5  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Sx\";" ascii
    $s6  = "ck(){return \"XCr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs" ascii
    $s7  = "k(){return \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\"" ascii
    $s8  = "turn \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s9  = "{return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s10 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}