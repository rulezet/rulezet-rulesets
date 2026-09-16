rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_85f2776f4fe6_5350 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash3       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"
    hash4       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "ion fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s2 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(" ascii
    $s3 = "fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s4 = "ck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s5 = ")(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}