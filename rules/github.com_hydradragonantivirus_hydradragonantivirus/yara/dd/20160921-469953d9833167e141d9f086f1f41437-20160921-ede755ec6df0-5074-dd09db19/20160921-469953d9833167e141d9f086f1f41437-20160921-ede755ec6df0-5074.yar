rule _20160921_469953d9833167e141d9f086f1f41437_20160921_ede755ec6df0_5074 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"

  strings:
    $s1 = "\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function " ascii
    $s2 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii
    $s3 = "rn \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s4 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XC" ascii
    $s5 = ",(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}