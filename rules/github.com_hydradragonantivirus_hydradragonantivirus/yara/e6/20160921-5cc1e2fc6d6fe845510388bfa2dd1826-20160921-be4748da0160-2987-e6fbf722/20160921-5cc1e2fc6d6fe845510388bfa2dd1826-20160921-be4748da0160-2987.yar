rule _20160921_5cc1e2fc6d6fe845510388bfa2dd1826_20160921_be4748da0160_2987 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "eturn \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s2 = "\"Nm\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s3 = "fuck(){return \"UXf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s4 = "\"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s5 = "(function fuck(){return \"We\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){re" ascii
    $s6 = "n \"RAi\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s7 = "eturn \"GJx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"USf\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}