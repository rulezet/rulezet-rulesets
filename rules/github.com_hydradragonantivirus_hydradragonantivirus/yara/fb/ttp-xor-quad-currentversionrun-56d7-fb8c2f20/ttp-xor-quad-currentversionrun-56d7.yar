rule TTP_XOR_QUAD_CurrentVersionRun_56d7 {
  strings:
    $key_56d7 = { 05 b8 [2] 21 b6 [2] 0a 9a [2] 24 b8 [2] 30 a3 [2] 3f b9 [2] 21 a4 [2] 23 a5 [2] 38 a3 [2] 24 a4 [2] 38 8b }

  condition:
    any of them
}