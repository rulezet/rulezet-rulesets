rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_4288 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash4       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"" ascii
    $s2 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"XHj\";})(),(" ascii
    $s3 = "(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s4 = "turn \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s5 = " fuck(){return \"IOs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}