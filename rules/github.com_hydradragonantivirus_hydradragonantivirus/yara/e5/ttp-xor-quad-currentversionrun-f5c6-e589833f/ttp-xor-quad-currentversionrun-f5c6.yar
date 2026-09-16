rule TTP_XOR_QUAD_CurrentVersionRun_f5c6 {
  strings:
    $key_f5c6 = { a6 a9 [2] 82 a7 [2] a9 8b [2] 87 a9 [2] 93 b2 [2] 9c a8 [2] 82 b5 [2] 80 b4 [2] 9b b2 [2] 87 b5 [2] 9b 9a }

  condition:
    any of them
}