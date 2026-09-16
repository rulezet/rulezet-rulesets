rule _20160517_663c7860c7965bcdb912703180425ce5_20160517_fe735d15168b_979 {
  meta:
    description = "datamaliciousorder - from files 20160517_663c7860c7965bcdb912703180425ce5.js, 20160517_fe735d15168b17f97829fe982eef79d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "598e15e89d95c941fd37f3ff99d94e1eaedb5f51524ab6626ef65fd52f62fcda"
    hash2       = "9eb9eb6eb75af5e0a484a93f13a1851bc0ad356234d2d05ed235c501e7c3f771"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* bu  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* bu  */(accinp0 /* bu  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* bu  */ = (123, Turkey); return devel0 /* bu  */;};" fullword ascii
    $s4 = "DENMARK1 /* bu  */= true;/* bu  */" fullword ascii
    $s5 = "function Scott /* bu  */(accinp0 /* bu  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s6 = "place = /* bu  */(/* bu  */\"noitisop\").split(''/* bu  */).reverse(/* bu  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}