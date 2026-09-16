rule _20160921_01da6b0c1b5614c5877e0dd7b6be4036_20160921_17642c69cbfb_4128 {
  meta:
    description = "datamaliciousorder - from files 20160921_01da6b0c1b5614c5877e0dd7b6be4036.js, 20160921_17642c69cbfb276056f3695ae22dad4c.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da941f7d098e0926acf7ad9efedc9f91495115fc83f288580eba79e44574693"
    hash2       = "4cdbf9fba4e3fec424cf182fd21fa3c400b0649ca09f140375a47df12248955c"
    hash3       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1 = "){return \"Mw\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s2 = ",(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){" ascii
    $s3 = "\"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"LGo\";})(),(funct" ascii
    $s4 = ";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuc" ascii
    $s5 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}