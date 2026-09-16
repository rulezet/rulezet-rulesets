rule _20160921_063094039ef79437a260d3dde960797a_20160921_0de23a42684a_510 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_a160e4a385807ffcdde4f99a0c57b6b2.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js, 20160921_b74bfd3dc7404d3d5a6512718aa52504.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash3       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash4       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash5       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash6       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash7       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"
    hash8       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash9       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash10      = "c3eeb2af6e453aec7ede2bba435e7dcf60f7497a94584d1908a2235d79c28a34"
    hash11      = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash12      = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"
    hash13      = "359d333ab8fc51d27349ecaec71f8baf8e8aafae5bfe2d6afd26f4ed76e802db"
    hash14      = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash15      = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"
    hash16      = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"
    hash17      = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1  = "function fuck(){return \"We\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){ret" ascii
    $s2  = "n fuck(){return \"Xg\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"I" ascii
    $s3  = "){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})" ascii
    $s4  = "unction fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii
    $s5  = "rn \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(fun" ascii
    $s6  = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Dc\";})(),(function" ascii
    $s7  = "rn \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(func" ascii
    $s8  = "w\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Na\";})(),(function f" ascii
    $s9  = "y\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s10 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"We\";})(),(function fuc" ascii
    $s11 = "rn \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s12 = "(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s13 = "ction fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s14 = "),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){r" ascii
    $s15 = "on fuck(){return \"Xw\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"U" ascii
    $s16 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Av\";})(),(fun" ascii
    $s17 = "uck(){return \"ZLd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw" ascii
    $s18 = "Ve\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s19 = "n \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(func" ascii
    $s20 = "return \"CCb\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}