rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_7463e4586b30_3711 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_99220520e87414c0f2e1267cf4078a22.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash3       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash4       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"
    hash5       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"

  strings:
    $s1 = "urn \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s2 = "),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s3 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii
    $s4 = " \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s5 = "){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})" ascii
    $s6 = "(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}