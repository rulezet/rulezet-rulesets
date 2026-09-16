rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_3a2902eaca0b_4233 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_acc098eb35e159f33783b155bb8929cb.js, 20160921_cda776f6c5cb6eec510c00d5294fbfae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash3       = "1f491f3a68df5684f7bb14dc15b8f6f3dea400dde990f144e6cf0792facdba6e"
    hash4       = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"

  strings:
    $s1 = "urn \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(fu" ascii
    $s2 = "TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(funct" ascii
    $s3 = "{return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})" ascii
    $s4 = "\"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s5 = "{return \"TTs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}