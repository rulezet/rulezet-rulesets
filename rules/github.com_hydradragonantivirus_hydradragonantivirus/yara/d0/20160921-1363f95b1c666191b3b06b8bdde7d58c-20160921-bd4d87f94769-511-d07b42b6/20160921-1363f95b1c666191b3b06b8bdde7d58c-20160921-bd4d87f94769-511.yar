rule _20160921_1363f95b1c666191b3b06b8bdde7d58c_20160921_bd4d87f94769_511 {
  meta:
    description = "datamaliciousorder - from files 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash2       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash3       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1  = "urn \"Cs\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(f" ascii
    $s2  = "n \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(fu" ascii
    $s3  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";" ascii
    $s4  = " \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(fu" ascii
    $s5  = "(function fuck(){return \"Fv\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){ret" ascii
    $s6  = "){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";}" ascii
    $s7  = "function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii
    $s8  = "fuck(){return \"XHj\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Za" ascii
    $s9  = "\"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(funct" ascii
    $s10 = "eturn \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"EHo\";})(),(" ascii
    $s11 = "n fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s12 = "urn \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(f" ascii
    $s13 = "uck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi" ascii
    $s14 = "})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s15 = "n \"Qh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s16 = "Jx\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s17 = "(function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s18 = "{return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})" ascii
    $s19 = "(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s20 = "Pu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}