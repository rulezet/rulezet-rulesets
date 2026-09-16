rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_1534 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"

  strings:
    $s1  = "})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuc" ascii
    $s2  = "on fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s3  = ")(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"SUi\";})(),(function fuck(" ascii
    $s4  = "(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"DAa\";})(),(function fuck" ascii
    $s5  = "n fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return " ascii
    $s6  = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Na\";})" ascii
    $s7  = "urn \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(fu" ascii
    $s8  = "Nm\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s9  = "ck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s10 = "){return \"Za\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})" ascii
    $s11 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){ret" ascii
    $s12 = "uck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}