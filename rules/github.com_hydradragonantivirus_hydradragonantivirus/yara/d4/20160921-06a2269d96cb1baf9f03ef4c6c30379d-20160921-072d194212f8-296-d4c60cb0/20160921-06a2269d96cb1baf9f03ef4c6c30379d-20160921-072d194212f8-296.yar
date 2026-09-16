rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_072d194212f8_296 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash3       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash4       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash5       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash6       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash7       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"

  strings:
    $s1  = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ar" ascii
    $s2  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){retu" ascii
    $s3  = "urn \"MIl\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4  = "ction fuck(){return \"Pc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s5  = "nction fuck(){return \"Pc\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii
    $s6  = "){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ar\";})(" ascii
    $s7  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return " ascii
    $s8  = "\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function " ascii
    $s9  = "rn \"Ik\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s10 = "(){return \"Jo\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Za\";})(" ascii
    $s11 = "})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s12 = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){ret" ascii
    $s13 = "(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function fuck(" ascii
    $s14 = "function fuck(){return \"Xw\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){re" ascii
    $s15 = "return \"Na\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(" ascii
    $s16 = "u\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"UOe\";})(),(function " ascii
    $s17 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){ret" ascii
    $s18 = "k(){return \"FJs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\"" ascii
    $s19 = "\"Nm\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s20 = "),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}