rule TTP_XOR_QUAD_CurrentVersionRun_f0d7 {
  strings:
    $key_f0d7 = { a3 b8 [2] 87 b6 [2] ac 9a [2] 82 b8 [2] 96 a3 [2] 99 b9 [2] 87 a4 [2] 85 a5 [2] 9e a3 [2] 82 a4 [2] 9e 8b }

  condition:
    any of them
}