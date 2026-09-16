rule _20160516_2afac5cdb41932ba1b997fda8944e55d_20160517_039e1b4621f4_1222 {
  meta:
    description = "datamaliciousorder - from files 20160516_2afac5cdb41932ba1b997fda8944e55d.js, 20160517_039e1b4621f4d93b73d6797c78398c4c.js, 20160517_4deee6fdb9997e565ba9c3ed395e6281.js, 20160517_554320a36ab7db7e57008760b8bfb464.js, 20160517_573f3da880cd1cec426c460a89c49650.js, 20160517_8277979bd9730e541abf708c1687a52c.js, 20160517_9df1ecc94eae1a565072c7caccf4ca7a.js, 20160517_f6f52fcd01d2b262db765467b24b7707.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c31ca842dec79e93887af0d5e84c9a96ea1ffda49fb848f39a87d2b66ac1a38"
    hash2       = "12cabf363c81d3c74ed908361db98db7b267f428779e7d05cc4b066de2ba0dd9"
    hash3       = "d5475be1623219a4539ea40fbf956c04032521e7392a7ae86c801c06c131b5dc"
    hash4       = "54cf94b4bdf4309a84828b51c389dbfd699af8fa86ea8676a1e11e837fc45642"
    hash5       = "4b6ee7288e4ef7b627dd666ff06d5681ce1a53c1f5427724ac902208b7b37f99"
    hash6       = "3c30efebdc0a6ff0e1474df1b255a54aab48f4fb5980d844982f899209af5461"
    hash7       = "be2d60e19bc1a489c4d321e29aac7c9ee795d79a98c7a7d4f138a2c1d8081389"
    hash8       = "972b5bc7064572d5857ed2410aa66dd71164c4125dd3630b69db8b2b2ecffe65"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* L  */ = (123, Turkey); return devel0 /* L  */;};" fullword ascii
    $s2 = "devel1[aaa](Turkey0 /* L  */, Currency, (true, false));" fullword ascii
    $s3 = "function Scott /* L  */(accinp0 /* L  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "place = /* L  */(/* L  */\"noitisop\").split(''/* L  */).reverse(/* L  */).join('');" fullword ascii
    $s5 = "function Scott /* L  */(accinp0 /* L  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "DENMARK1 /* L  */= true;/* L  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}