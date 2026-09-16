rule _20160921_d29f34806a7d94f2bbb7a733fc4c43bc_20160921_dbc1b5f3d038_5700 {
  meta:
    description = "datamaliciousorder - from files 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"
    hash2       = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"

  strings:
    $s1 = "nction fuck(){return \"Wo0\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s2 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";})(),(function f" ascii
    $s3 = "rn \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(fun" ascii
    $s4 = "ck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Yk\";" ascii
    $s5 = "})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}