rule TTP_XOR_QUAD_CurrentVersionRun_f5c8 {
  strings:
    $key_f5c8 = { a6 a7 [2] 82 a9 [2] a9 85 [2] 87 a7 [2] 93 bc [2] 9c a6 [2] 82 bb [2] 80 ba [2] 9b bc [2] 87 bb [2] 9b 94 }

  condition:
    any of them
}