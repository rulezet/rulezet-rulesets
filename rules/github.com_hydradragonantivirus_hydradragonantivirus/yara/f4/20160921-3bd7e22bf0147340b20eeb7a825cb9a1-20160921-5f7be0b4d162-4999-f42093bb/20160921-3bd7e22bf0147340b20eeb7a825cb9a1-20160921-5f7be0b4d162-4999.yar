rule _20160921_3bd7e22bf0147340b20eeb7a825cb9a1_20160921_5f7be0b4d162_4999 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash2       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash3       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash4       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"

  strings:
    $s1 = "rn \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s2 = "on fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s3 = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return" ascii
    $s4 = " fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"US" ascii
    $s5 = "b\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}