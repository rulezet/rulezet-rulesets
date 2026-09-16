rule _20160921_a8b3df7e98e8a886568b517b6d357d72_20160921_ac32e5db1761_5610 {
  meta:
    description = "datamaliciousorder - from files 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash2       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash3       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash4       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"

  strings:
    $s1 = "urn \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(fun" ascii
    $s2 = "ion fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii
    $s3 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s4 = "){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})" ascii
    $s5 = "Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}