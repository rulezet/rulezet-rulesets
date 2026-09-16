rule _20160921_65ff2a70ce98d58243fbbdf4849b9c40_20160921_7c37cf57d8ed_5325 {
  meta:
    description = "datamaliciousorder - from files 20160921_65ff2a70ce98d58243fbbdf4849b9c40.js, 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4be01014513bc9c23e14a62953fb7d9f955467208a844109b10c685b1f9c4f29"
    hash2       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash3       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash4       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = ";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s2 = "function fuck(){return \"Vf\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){re" ascii
    $s3 = "(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"DWe\";})" ascii
    $s5 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}