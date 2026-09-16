rule sig_20160517_2a104c104f9da5eac50ad12af2d085a9 {
  meta:
    description = "datamaliciousorder - file 20160517_2a104c104f9da5eac50ad12af2d085a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f9a10235a02459737d2bb9e93a950986c746b780ee37871439e047f519d994c"

  strings:
    $s1 = "var xumu='virdcsamssc3rn2wzn junlmhuqtmdbybs3xpjnobugqlm4rrjotmney2hxnonfesvhzl2enwzcbnicqyxm3=gcqhs\\'ksupqtvnzqgcmcwwkndvrpjil" ascii
    $s2 = "bject(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   scwajuv3oa=r4+\"v\"+\"al\";   WScript.lister=5;   scwajuv3oa=\"\"+\"s\";   ww=23232" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}