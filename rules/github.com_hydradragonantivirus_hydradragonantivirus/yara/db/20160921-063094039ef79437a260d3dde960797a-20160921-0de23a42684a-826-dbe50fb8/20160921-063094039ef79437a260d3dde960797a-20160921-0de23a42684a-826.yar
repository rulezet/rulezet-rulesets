rule _20160921_063094039ef79437a260d3dde960797a_20160921_0de23a42684a_826 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash3       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash4       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash5       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash6       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash7       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"
    hash8       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1  = "k(){return \"ZWu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\"" ascii
    $s2  = "ck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";" ascii
    $s3  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s4  = " \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s5  = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Z" ascii
    $s6  = "fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\"" ascii
    $s7  = "rn \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s8  = "(function fuck(){return \"Na\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){ret" ascii
    $s9  = "ck(){return \"Yk\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\"" ascii
    $s10 = "Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s11 = "){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"To\";})" ascii
    $s12 = "eturn \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s13 = "){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"EHo\";})" ascii
    $s14 = "urn \"Nm\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s15 = "tion fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s16 = ",(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){r" ascii
    $s17 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return " ascii
    $s18 = "rn \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s19 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retur" ascii
    $s20 = "(){return \"Ug\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}