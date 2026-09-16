rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_7463e4586b30_1852 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash3       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash4       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1  = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){" ascii
    $s2  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){ret" ascii
    $s3  = "function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){re" ascii
    $s4  = "(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Cd\";" ascii
    $s5  = "We\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s6  = "fuck(){return \"Et\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx" ascii
    $s7  = "rn \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s8  = "nction fuck(){return \"QTc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s9  = ")(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(" ascii
    $s10 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}