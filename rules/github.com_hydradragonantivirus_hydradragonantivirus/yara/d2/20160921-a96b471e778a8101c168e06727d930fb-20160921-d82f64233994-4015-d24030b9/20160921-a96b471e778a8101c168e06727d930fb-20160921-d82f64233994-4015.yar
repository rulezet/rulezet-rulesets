rule _20160921_a96b471e778a8101c168e06727d930fb_20160921_d82f64233994_4015 {
  meta:
    description = "datamaliciousorder - from files 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash2       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1 = "),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s2 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s3 = "g\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"EHo\";})(),(function" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii
    $s5 = "{return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})" ascii
    $s6 = ")(),(function fuck(){return \"We\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"OQr\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}