rule TTP_XOR_QUAD_CurrentVersionRun_f5c9 {
  strings:
    $key_f5c9 = { a6 a6 [2] 82 a8 [2] a9 84 [2] 87 a6 [2] 93 bd [2] 9c a7 [2] 82 ba [2] 80 bb [2] 9b bd [2] 87 ba [2] 9b 95 }

  condition:
    any of them
}