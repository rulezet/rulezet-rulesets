rule _20160517_4d525b0411a2f184b53852a39886d5a8_20160517_536bb496511b_1255 {
  meta:
    description = "datamaliciousorder - from files 20160517_4d525b0411a2f184b53852a39886d5a8.js, 20160517_536bb496511b21aeb4a7ee072138737b.js, 20160517_a7ed831b93e692e587f63141208a63c7.js, 20160517_f39ed64fb5dd04696e9de35e390dcb61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fab7da50c439ccbaea1aa968a951884fa4fc9ca46f96a73ade52441d6de1894"
    hash2       = "a21691118828cd52bca33d5397979976ba8d3914d18426ed65c2c699fb10cec9"
    hash3       = "55a2d904dbc8623d0dd4a8220e75ea2056b8e65dddf0ce265970b403b7e7a659"
    hash4       = "31952f1ed06be9036765a1b7c6d0322879864ea3dc8d06259342c9b3b0775ce1"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* I  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* I  */ = (123, Turkey); return devel0 /* I  */;};" fullword ascii
    $s3 = "function Scott /* I  */(accinp0 /* I  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "place = /* I  */(/* I  */\"noitisop\").split(''/* I  */).reverse(/* I  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* I  */= true;/* I  */" fullword ascii
    $s6 = "function Scott /* I  */(accinp0 /* I  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}