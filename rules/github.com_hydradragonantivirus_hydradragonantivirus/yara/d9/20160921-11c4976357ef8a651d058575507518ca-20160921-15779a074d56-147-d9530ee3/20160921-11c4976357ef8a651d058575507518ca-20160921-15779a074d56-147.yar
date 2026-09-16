rule _20160921_11c4976357ef8a651d058575507518ca_20160921_15779a074d56_147 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js, 20160921_df51150cb4977f20502f85bfda11d939.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash3       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash4       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash5       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash6       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash7       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash8       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash9       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash10      = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash11      = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"
    hash12      = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"
    hash13      = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1  = "\"Wn\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(funct" ascii
    $s2  = "n \"AUx\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s3  = "turn \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s4  = "){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IOs\";})(" ascii
    $s5  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return" ascii
    $s6  = "ck(){return \"Ot\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\"" ascii
    $s7  = "urn \"GJx\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s8  = "){return \"GJx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s9  = "return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})()," ascii
    $s10 = "urn \"GJx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s11 = "Tc\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s12 = "n fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii
    $s13 = "eturn \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s14 = " \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s15 = "return \"Xg\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Xw\";})()," ascii
    $s16 = "MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ai\";})(),(functio" ascii
    $s17 = "n \"Yk\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s18 = "){return \"Ve\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})" ascii
    $s19 = "n \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xg\";})(),(func" ascii
    $s20 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}