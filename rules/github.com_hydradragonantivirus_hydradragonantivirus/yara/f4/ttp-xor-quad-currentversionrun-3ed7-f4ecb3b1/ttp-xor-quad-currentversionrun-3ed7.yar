rule TTP_XOR_QUAD_CurrentVersionRun_3ed7 {
  strings:
    $key_3ed7 = { 6d b8 [2] 49 b6 [2] 62 9a [2] 4c b8 [2] 58 a3 [2] 57 b9 [2] 49 a4 [2] 4b a5 [2] 50 a3 [2] 4c a4 [2] 50 8b }

  condition:
    any of them
}