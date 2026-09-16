rule _20160921_70d636d209e6f109a21746567376cc81_20160921_fc08be0621d4_1603 {
  meta:
    description = "datamaliciousorder - from files 20160921_70d636d209e6f109a21746567376cc81.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e26044e7a07a5a675f3b388e6309b138b9e7a1aa61556485f444025164a158e"
    hash2       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1  = "),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s2  = "g\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function f" ascii
    $s3  = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw" ascii
    $s4  = "j\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s5  = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(functi" ascii
    $s6  = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})()," ascii
    $s7  = "function fuck(){return \"Ar\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){re" ascii
    $s8  = ",(function fuck(){return \"MUs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s9  = "{return \"Yk\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s10 = "rn \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s11 = "(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s12 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}