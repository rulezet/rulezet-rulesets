rule TTP_XOR_QUAD_CurrentVersionRun_f2d7 {
  strings:
    $key_f2d7 = { a1 b8 [2] 85 b6 [2] ae 9a [2] 80 b8 [2] 94 a3 [2] 9b b9 [2] 85 a4 [2] 87 a5 [2] 9c a3 [2] 80 a4 [2] 9c 8b }

  condition:
    any of them
}