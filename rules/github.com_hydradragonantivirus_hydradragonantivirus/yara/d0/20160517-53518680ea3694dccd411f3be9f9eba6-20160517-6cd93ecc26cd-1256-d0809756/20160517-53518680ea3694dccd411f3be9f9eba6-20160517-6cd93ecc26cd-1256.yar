rule _20160517_53518680ea3694dccd411f3be9f9eba6_20160517_6cd93ecc26cd_1256 {
  meta:
    description = "datamaliciousorder - from files 20160517_53518680ea3694dccd411f3be9f9eba6.js, 20160517_6cd93ecc26cddaa81b1e132704a17436.js, 20160517_792526f8642cc9374cc7937fa1aa8257.js, 20160517_e97e14f4a6fa17b807f1a49963467180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fa6f5168c4a690f7693e1f0cbed49f2a02eb70bcc36bfc2ab3b7122a0b85d85"
    hash2       = "7baa5f4eb15bc891379ff40c6ec6e68df1ee4c562dbd96917ad999f450b01365"
    hash3       = "16fb75f8c4bb2cc0a6d52c6d94f82d735aa0723607fc2e24453a4662eaa4270e"
    hash4       = "6c20ee549053494f6de174333109b25cf7bdf2a6eceac0a54c86fc871d9c0f9b"

  strings:
    $s1 = "function Scott /* f  */(accinp0 /* f  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* f  */ = (123, Turkey); return devel0 /* f  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* f  */, Currency, (true, false));" fullword ascii
    $s4 = "DENMARK1 /* f  */= true;/* f  */" fullword ascii
    $s5 = "function Scott /* f  */(accinp0 /* f  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "place = /* f  */(/* f  */\"noitisop\").split(''/* f  */).reverse(/* f  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}