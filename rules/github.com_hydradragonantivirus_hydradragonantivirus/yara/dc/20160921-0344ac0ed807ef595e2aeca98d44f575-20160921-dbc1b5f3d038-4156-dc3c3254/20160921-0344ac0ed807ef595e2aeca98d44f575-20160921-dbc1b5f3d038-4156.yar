rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_dbc1b5f3d038_4156 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js, 20160921_e6771cfa257410eb61913de76cb777a8.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"
    hash3       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"
    hash4       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1 = "ck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe" ascii
    $s2 = " \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s3 = "uck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s4 = ",(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){" ascii
    $s5 = "\"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}