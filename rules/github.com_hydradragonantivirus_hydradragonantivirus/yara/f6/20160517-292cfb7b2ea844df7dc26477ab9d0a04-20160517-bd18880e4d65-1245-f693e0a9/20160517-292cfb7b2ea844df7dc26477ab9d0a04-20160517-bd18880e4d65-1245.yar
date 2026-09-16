rule _20160517_292cfb7b2ea844df7dc26477ab9d0a04_20160517_bd18880e4d65_1245 {
  meta:
    description = "datamaliciousorder - from files 20160517_292cfb7b2ea844df7dc26477ab9d0a04.js, 20160517_bd18880e4d6577a9cbb176982e8ecd43.js, 20160517_bff3ce8fc6a5af21b93ebf5d95df137c.js, 20160517_c016836ab909f6d9cbd13afc88a35627.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c006df9da9b1c52d46f52e8b96afdaab04efeaa703c6312a737dfcaa6e8c414"
    hash2       = "4a22c4ac7879da6aa997c295d4c2f5e39a266ff776558e2f4196ed8ee1004fc3"
    hash3       = "da270f67efa42f864a0c84c9d7ed9dffd2d73fbea3916d61af9862e9bc07e2ea"
    hash4       = "345fc88dfbb01fdfe3e95eb5ca85145660eb5db8515c294931fed6f981117136"

  strings:
    $s1 = "function Scott /* Z  */(accinp0 /* Z  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* Z  */ = (123, Turkey); return devel0 /* Z  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* Z  */, Currency, (true, false));" fullword ascii
    $s4 = "place = /* Z  */(/* Z  */\"noitisop\").split(''/* Z  */).reverse(/* Z  */).join('');" fullword ascii
    $s5 = "function Scott /* Z  */(accinp0 /* Z  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "DENMARK1 /* Z  */= true;/* Z  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}