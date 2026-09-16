rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_5033 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash3       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"

  strings:
    $s1 = "turn \"SUi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})()" ascii
    $s2 = "urn \"Sx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s3 = "\"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(func" ascii
    $s4 = "(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";" ascii
    $s5 = "rn \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}