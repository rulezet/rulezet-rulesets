rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_3bd7e22bf014_3595 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash3       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"

  strings:
    $s1 = "),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck()" ascii
    $s2 = "uck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Zy" ascii
    $s3 = "ction fuck(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s4 = "function fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s5 = "uck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UO" ascii
    $s6 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Na\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}