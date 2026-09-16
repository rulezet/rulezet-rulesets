rule _20160517_6d496a5b08c1e6417b9dc2b3ab5a7f33_20160517_75a4e88643ac_1258 {
  meta:
    description = "datamaliciousorder - from files 20160517_6d496a5b08c1e6417b9dc2b3ab5a7f33.js, 20160517_75a4e88643ac5c271ca22411220b37ee.js, 20160517_b5e2a9d6d75ff4697789fae8b9882ffe.js, 20160517_dfdf691be09dee09a2e4cc37c6891f98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76bed0977848fcd483f9f355fd365094ab0ac27fc2247982b32bbb1ded3965c3"
    hash2       = "a72c4bdfb06a98101e881df62db3999710efe3aa8f3c8bf7505cad458554affe"
    hash3       = "e5a45fbcce1bb1adba85c966616212d530094ab43f28338b1fcd8abc79b174ae"
    hash4       = "273d957bd2ab1d197b51eb3f8ad9b7a41600cf8bb6e6dba2ad63720ca003971c"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* o  */ = (123, Turkey); return devel0 /* o  */;};" fullword ascii
    $s2 = "function Scott /* o  */(accinp0 /* o  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "devel1[aaa](Turkey0 /* o  */, Currency, (true, false));" fullword ascii
    $s4 = "DENMARK1 /* o  */= true;/* o  */" fullword ascii
    $s5 = "place = /* o  */(/* o  */\"noitisop\").split(''/* o  */).reverse(/* o  */).join('');" fullword ascii
    $s6 = "function Scott /* o  */(accinp0 /* o  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}