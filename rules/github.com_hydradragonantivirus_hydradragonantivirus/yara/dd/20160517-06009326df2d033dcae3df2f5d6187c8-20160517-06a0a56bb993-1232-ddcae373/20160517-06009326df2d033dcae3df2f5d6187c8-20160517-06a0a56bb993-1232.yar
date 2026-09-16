rule _20160517_06009326df2d033dcae3df2f5d6187c8_20160517_06a0a56bb993_1232 {
  meta:
    description = "datamaliciousorder - from files 20160517_06009326df2d033dcae3df2f5d6187c8.js, 20160517_06a0a56bb993908191b82ae9cf3997a8.js, 20160517_7f8679dbd0c1038bb55c895d0eb4c355.js, 20160517_9780bb57269d77dab52d50aa80cb5a0e.js, 20160517_da26eda147b6d6157b18015c1ef9a92e.js, 20160517_e757c57b0d8f6e3ccab93d69143cee3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3b44e703b08d07502130d6d2fe82c9f826b5b4853616179834e1df46f515df7"
    hash2       = "f6ff7e90a599b8ef36b60bf9ab845702628e6b6676bbfe335bc0929f5e1d73df"
    hash3       = "1b33235adc639914cadf4765b5a97419eff4c24052698d8abb99ce24a253f77e"
    hash4       = "87c7f0d0431fc81356e76677dd51557c04e55971c14ac55dec36de4ea47b9a86"
    hash5       = "c91ce8f0b3f58ba77c5e7f6bffa0517551ac4b0198b4a0eca6d4c2460c4a6df9"
    hash6       = "7a53c040165d71d49acae5fa99b5967bc907f39fc3ae91533090ccf18e44ab65"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* v  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* v  */ = (123, Turkey); return devel0 /* v  */;};" fullword ascii
    $s3 = "function Scott /* v  */(accinp0 /* v  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "DENMARK1 /* v  */= true;/* v  */" fullword ascii
    $s5 = "place = /* v  */(/* v  */\"noitisop\").split(''/* v  */).reverse(/* v  */).join('');" fullword ascii
    $s6 = "function Scott /* v  */(accinp0 /* v  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}