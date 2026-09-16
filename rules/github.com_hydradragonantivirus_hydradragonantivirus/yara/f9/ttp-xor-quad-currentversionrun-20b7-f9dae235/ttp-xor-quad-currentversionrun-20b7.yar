rule TTP_XOR_QUAD_CurrentVersionRun_20b7 {
  strings:
    $key_20b7 = { 73 d8 [2] 57 d6 [2] 7c fa [2] 52 d8 [2] 46 c3 [2] 49 d9 [2] 57 c4 [2] 55 c5 [2] 4e c3 [2] 52 c4 [2] 4e eb }

  condition:
    any of them
}