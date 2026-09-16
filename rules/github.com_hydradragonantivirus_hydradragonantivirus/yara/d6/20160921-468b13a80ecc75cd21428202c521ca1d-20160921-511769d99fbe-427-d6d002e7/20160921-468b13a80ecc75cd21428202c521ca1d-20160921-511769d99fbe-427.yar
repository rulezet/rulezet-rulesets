rule _20160921_468b13a80ecc75cd21428202c521ca1d_20160921_511769d99fbe_427 {
  meta:
    description = "datamaliciousorder - from files 20160921_468b13a80ecc75cd21428202c521ca1d.js, 20160921_511769d99fbe4d59a2e55781fb0eb77c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"
    hash2       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"

  strings:
    $s1  = "eturn \"MIl\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s2  = "function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){re" ascii
    $s3  = " fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"A" ascii
    $s4  = "){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})" ascii
    $s5  = "n fuck(){return \"Fv\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"O" ascii
    $s6  = "n fuck(){return \"YQt\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s7  = "ck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s8  = "ion fuck(){return \"ZLd\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s9  = "eturn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"KVh\";})(" ascii
    $s10 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MUs\";})(),(f" ascii
    $s11 = "),(function fuck(){return \"Oh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){" ascii
    $s12 = " \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"To\";})(),(funct" ascii
    $s13 = "(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s14 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"VMi\";})(),(function fuck(){return \"" ascii
    $s15 = ",(function fuck(){return \"Na\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s16 = "(),(function fuck(){return \"To\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){" ascii
    $s17 = ",(function fuck(){return \"Sx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){r" ascii
    $s18 = "return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s19 = ";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fu" ascii
    $s20 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}