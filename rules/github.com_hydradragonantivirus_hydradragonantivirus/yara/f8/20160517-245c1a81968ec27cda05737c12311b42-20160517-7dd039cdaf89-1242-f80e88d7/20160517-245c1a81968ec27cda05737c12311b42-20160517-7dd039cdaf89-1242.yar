rule _20160517_245c1a81968ec27cda05737c12311b42_20160517_7dd039cdaf89_1242 {
  meta:
    description = "datamaliciousorder - from files 20160517_245c1a81968ec27cda05737c12311b42.js, 20160517_7dd039cdaf89da6b93a5c54496b96732.js, 20160517_ace6e31f87acc598e303251db5b199f6.js, 20160517_dd286088696d2b2e3432675304f2fb71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0486f963ffad0b0d0db3e8a0609de4dcaf4e3cc507db53ea2701b873de1565b4"
    hash2       = "f24b9749bb5c3d786bdcb33009c11cdb2b2e69f709aa8e48f1352de7b53bff30"
    hash3       = "9360f4f0e206b524ed34022beb87f229945354093ec8629856e60377e01f5a62"
    hash4       = "11cfb13bccfe181b80a2f125450b98e98c578fd7620d00de7c472f4879212cb4"

  strings:
    $s1 = "function Scott /* y  */(accinp0 /* y  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* y  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* y  */ = (123, Turkey); return devel0 /* y  */;};" fullword ascii
    $s4 = "place = /* y  */(/* y  */\"noitisop\").split(''/* y  */).reverse(/* y  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* y  */= true;/* y  */" fullword ascii
    $s6 = "function Scott /* y  */(accinp0 /* y  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}