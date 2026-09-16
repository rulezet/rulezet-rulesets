rule _20160516_9d043cf9cf1081ed931a806c3c649bb7_20160517_3babca3c749e_1225 {
  meta:
    description = "datamaliciousorder - from files 20160516_9d043cf9cf1081ed931a806c3c649bb7.js, 20160517_3babca3c749e4ea21704dce0f828bf8f.js, 20160517_d070888d79da309f448b59c0e4a75643.js, 20160517_d7b0d922c26945c372f0bb3894161a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a030fe88a4c6d69a8e88750300405b6ce8ccb84d6c8d985b2d3f0c6bf2f305f"
    hash2       = "9cf9f2b017490b301ac55f4c9b012b155ea1d8bfb834734fa64f6d05f7ba86fb"
    hash3       = "72c192993533ad0624375b36da3d292b12fa0ace199223cef20ab88acba00ef6"
    hash4       = "d33c7717bf91428c8135ee9a0945f637efae6e496cbf575bad94787dae006b87"

  strings:
    $s1 = "function Scott /* C  */(accinp0 /* C  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* C  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* C  */ = (123, Turkey); return devel0 /* C  */;};" fullword ascii
    $s4 = "function Scott /* C  */(accinp0 /* C  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* C  */= true;/* C  */" fullword ascii
    $s6 = "place = /* C  */(/* C  */\"noitisop\").split(''/* C  */).reverse(/* C  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}