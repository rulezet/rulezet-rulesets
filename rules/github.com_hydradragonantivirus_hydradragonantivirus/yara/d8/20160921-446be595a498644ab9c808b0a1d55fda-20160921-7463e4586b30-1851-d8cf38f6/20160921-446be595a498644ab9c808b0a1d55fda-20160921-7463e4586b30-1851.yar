rule _20160921_446be595a498644ab9c808b0a1d55fda_20160921_7463e4586b30_1851 {
  meta:
    description = "datamaliciousorder - from files 20160921_446be595a498644ab9c808b0a1d55fda.js, 20160921_7463e4586b309c15d7048a37c63c1226.js, 20160921_884f773b3c246c835029fc91499fb017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735df5a75dd8a8fa643384cdee60651aafaebc84d57deefb035eb570ba25a521"
    hash2       = "96a40a72711934aeffde8b64056102f9e3de80fa22eecc0a25cf9c045d3ab190"
    hash3       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"

  strings:
    $s1  = " fuck(){return \"DWe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"N" ascii
    $s2  = "unction fuck(){return \"Yk\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){retu" ascii
    $s3  = "Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s4  = "\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function" ascii
    $s5  = " \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(fun" ascii
    $s6  = "ction fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s7  = "{return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})" ascii
    $s8  = "{return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})" ascii
    $s9  = "uck(){return \"DWe\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s10 = "rn \"DWe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}