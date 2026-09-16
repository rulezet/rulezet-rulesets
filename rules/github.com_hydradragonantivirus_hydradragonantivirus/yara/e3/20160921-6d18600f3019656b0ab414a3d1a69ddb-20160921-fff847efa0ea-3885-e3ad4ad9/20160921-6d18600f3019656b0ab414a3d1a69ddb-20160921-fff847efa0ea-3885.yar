rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_fff847efa0ea_3885 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = ",(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){r" ascii
    $s2 = "000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi" ascii
    $s3 = "nction f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s4 = "turn \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s5 = "Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(functio" ascii
    $s6 = "{return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Wb\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}