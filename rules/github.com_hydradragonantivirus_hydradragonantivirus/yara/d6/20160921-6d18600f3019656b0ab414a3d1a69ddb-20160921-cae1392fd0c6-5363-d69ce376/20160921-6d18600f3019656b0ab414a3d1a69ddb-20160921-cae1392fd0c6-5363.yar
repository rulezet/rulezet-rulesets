rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_cae1392fd0c6_5363 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "),(function f000(){return \"MMz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Vj\";})(),(function f000()" ascii
    $s2 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DYx\";})()," ascii
    $s3 = "00(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\"" ascii
    $s4 = "0(){return \"Lp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";}" ascii
    $s5 = "(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MBb\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}