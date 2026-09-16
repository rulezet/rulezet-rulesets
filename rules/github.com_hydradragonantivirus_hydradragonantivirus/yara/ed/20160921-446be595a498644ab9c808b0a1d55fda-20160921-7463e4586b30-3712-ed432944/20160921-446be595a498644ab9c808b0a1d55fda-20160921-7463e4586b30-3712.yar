rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_7463e4586b30_3712 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash3       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "rn \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s2 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return " ascii
    $s3 = "function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){ret" ascii
    $s4 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){retur" ascii
    $s5 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s6 = "ction fuck(){return \"Jh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}