rule sig_20160517_3683263556e0706447e370274bb289a5 {
  meta:
    description = "datamaliciousorder - file 20160517_3683263556e0706447e370274bb289a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c52ee57335a612632235be49ffc9430c2ebb86a1bb7044e9243ad6bf8c570d4"

  strings:
    $s1 = "var xumu='virdcsamssc3rn2wzn junlmhuqtmdbybs3xpjnobugqlm4rrjotmney2hxnonfesvhzl2enwzcbnicqyxm3=gcqhs\\'ksupqtvnzqgcmcwwkndvrpjil" ascii
    $s2 = "bject(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   scwajuv3oa=r4+\"v\"+\"al\";   WScript.lister=5;   scwajuv3oa=\"\"+\"s\";   ww=23232" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}