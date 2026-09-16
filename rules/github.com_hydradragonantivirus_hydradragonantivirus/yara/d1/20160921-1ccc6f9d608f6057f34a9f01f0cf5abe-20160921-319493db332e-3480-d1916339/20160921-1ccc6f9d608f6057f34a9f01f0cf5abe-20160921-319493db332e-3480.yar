rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_319493db332e_3480 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_319493db332e8496aaa88d74f25f0b8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"

  strings:
    $s1 = "ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(functi" ascii
    $s2 = ";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s3 = "ction f000(){return \"EZu\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retu" ascii
    $s4 = "(){return \"Qa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";}" ascii
    $s5 = "{return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})" ascii
    $s6 = "tion f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}