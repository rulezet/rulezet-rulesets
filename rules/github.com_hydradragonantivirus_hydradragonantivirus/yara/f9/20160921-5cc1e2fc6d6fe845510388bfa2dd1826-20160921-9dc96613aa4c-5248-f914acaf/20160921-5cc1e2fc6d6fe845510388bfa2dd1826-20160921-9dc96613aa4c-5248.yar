rule _20160921_5cc1e2fc6d6fe845510388bfa2dd1826_20160921_9dc96613aa4c_5248 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_9dc96613aa4c64f92e4ff218607f50d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash2       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"

  strings:
    $s1 = "(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(" ascii
    $s2 = "\"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii
    $s3 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s4 = ")(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuc" ascii
    $s5 = "){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}