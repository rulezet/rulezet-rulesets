rule _20160517_71afe8d71dad71f6cd1c4c83b378e58e_20160517_77171d75981d_1259 {
  meta:
    description = "datamaliciousorder - from files 20160517_71afe8d71dad71f6cd1c4c83b378e58e.js, 20160517_77171d75981d0e6b4a4a9dc8d1ad9630.js, 20160517_79d3021de5d472f7a453b1debe98bfdb.js, 20160517_97ef6b68b601dd7717fefe13258ad59d.js, 20160517_cb845cbe6d4659e22d560fdaa5444f43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db4ffba107f303021c5bb7938672a6d7da672929d5fed9af5a1263c9d5e5aede"
    hash2       = "fd157ce497918d5feb15a153286dbbf9416c2e70f68cc7b86583748d27fc0c8e"
    hash3       = "09c984808830b83d8b98147c68e825465157ae70d5d2389c8c92474db8896711"
    hash4       = "684d7451d4089759c9b497b2fe325bde043fe491e626e4b3b321e7cbe9072036"
    hash5       = "eeb61322e50b06149bb5c9eb04b1277f882c7c6d5629238ff564e12214ed56b5"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* i  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* i  */(accinp0 /* i  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* i  */ = (123, Turkey); return devel0 /* i  */;};" fullword ascii
    $s4 = "DENMARK1 /* i  */= true;/* i  */" fullword ascii
    $s5 = "function Scott /* i  */(accinp0 /* i  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "place = /* i  */(/* i  */\"noitisop\").split(''/* i  */).reverse(/* i  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}