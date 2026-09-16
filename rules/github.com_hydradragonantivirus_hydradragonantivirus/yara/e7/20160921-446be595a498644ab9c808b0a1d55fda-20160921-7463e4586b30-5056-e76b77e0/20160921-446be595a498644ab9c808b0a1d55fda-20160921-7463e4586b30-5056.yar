rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_7463e4586b30_5056 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash3       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash4       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash5       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash6       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash7       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"
    hash8       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"
    hash9       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1 = "(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})" ascii
    $s2 = "(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){" ascii
    $s3 = ")(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck" ascii
    $s4 = " \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(funct" ascii
    $s5 = "uck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}