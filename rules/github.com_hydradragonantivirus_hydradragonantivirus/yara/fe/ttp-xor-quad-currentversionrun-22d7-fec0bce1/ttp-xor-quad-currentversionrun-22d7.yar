rule TTP_XOR_QUAD_CurrentVersionRun_22d7 {
  strings:
    $key_22d7 = { 71 b8 [2] 55 b6 [2] 7e 9a [2] 50 b8 [2] 44 a3 [2] 4b b9 [2] 55 a4 [2] 57 a5 [2] 4c a3 [2] 50 a4 [2] 4c 8b }

  condition:
    any of them
}