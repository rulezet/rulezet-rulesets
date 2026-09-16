rule TTP_XOR_QUAD_CurrentVersionRun_f086 {
  strings:
    $key_f086 = { a3 e9 [2] 87 e7 [2] ac cb [2] 82 e9 [2] 96 f2 [2] 99 e8 [2] 87 f5 [2] 85 f4 [2] 9e f2 [2] 82 f5 [2] 9e da }

  condition:
    any of them
}