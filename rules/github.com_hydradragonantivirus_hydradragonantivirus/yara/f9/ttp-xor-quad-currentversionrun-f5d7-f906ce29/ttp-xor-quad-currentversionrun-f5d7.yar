rule TTP_XOR_QUAD_CurrentVersionRun_f5d7 {
  strings:
    $key_f5d7 = { a6 b8 [2] 82 b6 [2] a9 9a [2] 87 b8 [2] 93 a3 [2] 9c b9 [2] 82 a4 [2] 80 a5 [2] 9b a3 [2] 87 a4 [2] 9b 8b }

  condition:
    any of them
}