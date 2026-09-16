rule _20160921_207d0a8168d3fb16019724b9f72c41ba_20160921_48288731baa0_897 {
  meta:
    description = "datamaliciousorder - from files 20160921_207d0a8168d3fb16019724b9f72c41ba.js, 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js, 20160921_e6771cfa257410eb61913de76cb777a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b56af8225bf5087b8c8ea31ab85a80e0951c3a32b8a0a0be7e09ef2efc8172"
    hash2       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash3       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash4       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash5       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash6       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash7       = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"
    hash8       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"
    hash9       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"
    hash10      = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"
    hash11      = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"
    hash12      = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"

  strings:
    $s1  = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return " ascii
    $s2  = "unction fuck(){return \"Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s3  = "u\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ar\";})(),(function f" ascii
    $s4  = "unction fuck(){return \"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s5  = "v\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s6  = "){return \"GJx\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s7  = "function fuck(){return \"Xw\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retu" ascii
    $s8  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){retu" ascii
    $s9  = "w\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function" ascii
    $s10 = "ck(){return \"Et\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";" ascii
    $s11 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"A" ascii
    $s12 = "turn \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s13 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"UXf\";})(),(fun" ascii
    $s14 = "{return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"LGo\";})" ascii
    $s15 = ")(),(function fuck(){return \"Et\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck()" ascii
    $s16 = "urn \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s17 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"IOs\";})(" ascii
    $s18 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return" ascii
    $s19 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s20 = "n \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}