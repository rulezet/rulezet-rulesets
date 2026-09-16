rule _20160921_766f6fcbd2a94a55747a3f5b9a204b0e_20160921_bd4d87f94769_963 {
  meta:
    description = "datamaliciousorder - from files 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash2       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash3       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){retu" ascii
    $s2  = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(fu" ascii
    $s3  = "turn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})()," ascii
    $s4  = "uck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"VMi" ascii
    $s5  = "),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"To\";})(),(function fuck(){r" ascii
    $s6  = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function" ascii
    $s7  = "rn \"ZLd\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(f" ascii
    $s8  = "){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})" ascii
    $s9  = "k(){return \"Mw\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s10 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s11 = "n \"CCb\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s12 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jg\";})(),(function fuck(" ascii
    $s13 = "n fuck(){return \"XCr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"I" ascii
    $s14 = "fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Xw" ascii
    $s15 = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retur" ascii
    $s16 = "turn \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})()," ascii
    $s17 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return" ascii
    $s18 = "x\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s19 = ")(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZLd\";})(),(function fuc" ascii
    $s20 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"XHj\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}