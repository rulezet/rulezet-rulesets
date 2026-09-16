rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_e0f34764de4f_5367 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s2 = "rn \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f" ascii
    $s4 = "urn \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s5 = "n f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}