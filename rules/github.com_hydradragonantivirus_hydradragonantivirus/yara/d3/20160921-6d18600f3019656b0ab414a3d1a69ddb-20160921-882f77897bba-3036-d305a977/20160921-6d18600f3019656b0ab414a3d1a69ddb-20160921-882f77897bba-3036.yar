rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_882f77897bba_3036 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_882f77897bba85afdc56810c29ef4cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"

  strings:
    $s1 = "),(function f000(){return \"Km\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s2 = "turn \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s3 = "(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NYh\";}" ascii
    $s4 = "00(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vu\"" ascii
    $s5 = " \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s6 = "})(),(function f000(){return \"Yv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f00" ascii
    $s7 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}