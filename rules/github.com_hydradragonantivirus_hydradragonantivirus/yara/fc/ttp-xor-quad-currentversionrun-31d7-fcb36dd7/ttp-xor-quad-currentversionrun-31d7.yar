rule TTP_XOR_QUAD_CurrentVersionRun_31d7 {
  strings:
    $key_31d7 = { 62 b8 [2] 46 b6 [2] 6d 9a [2] 43 b8 [2] 57 a3 [2] 58 b9 [2] 46 a4 [2] 44 a5 [2] 5f a3 [2] 43 a4 [2] 5f 8b }

  condition:
    any of them
}