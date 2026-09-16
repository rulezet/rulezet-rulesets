rule _20160921_e2617d9e437c12b61ada4700f8e426b8_20160921_e6977bb87c75_4074 {
  meta:
    description = "datamaliciousorder - from files 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash2       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1 = "(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";}" ascii
    $s2 = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){" ascii
    $s3 = "ction fuck(){return \"Xg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return" ascii
    $s4 = "return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s5 = "fuck(){return \"MUs\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu" ascii
    $s6 = "\"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Zy\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}