rule sig_20160517_dd2148b1f1c69cfb4880a4027dc25896 {
  meta:
    description = "datamaliciousorder - file 20160517_dd2148b1f1c69cfb4880a4027dc25896.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23aba3fe2d55da0a10ec868519662490949c5ff8c2603b0a200e7139315c7d74"

  strings:
    $s1 = "var luf='vk44vjafmskurvsahh qqy4jqptwavlbkwekrazncv3eoht3ifzugg2nb2aeaxu2hzny1jtewdvel2=tmplg\\'srgn2tntdsyctesmpnzjqbcic42dpfoh" ascii
    $s2 = "VBS\"+\"cript\"+\".RegE\"+\"xp\");   dfvvkrko=r4+\"v\"+\"al\";   WScript.lister=5;   dfvvkrko=\"\"+\"s\";   ww=232323;   }catch(" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}