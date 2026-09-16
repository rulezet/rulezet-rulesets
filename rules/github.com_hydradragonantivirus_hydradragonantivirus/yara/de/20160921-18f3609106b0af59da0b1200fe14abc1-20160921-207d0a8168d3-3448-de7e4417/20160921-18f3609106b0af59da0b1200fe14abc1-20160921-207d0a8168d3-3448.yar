rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_207d0a8168d3_3448 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash3       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash4       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash5       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash6       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"
    hash7       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s2 = "ction fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retur" ascii
    $s3 = "rn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s4 = "return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(" ascii
    $s5 = "LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(funct" ascii
    $s6 = "function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}