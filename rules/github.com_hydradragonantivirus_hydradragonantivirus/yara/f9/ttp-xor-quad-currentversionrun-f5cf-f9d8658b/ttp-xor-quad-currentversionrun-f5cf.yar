rule TTP_XOR_QUAD_CurrentVersionRun_f5cf {
  strings:
    $key_f5cf = { a6 a0 [2] 82 ae [2] a9 82 [2] 87 a0 [2] 93 bb [2] 9c a1 [2] 82 bc [2] 80 bd [2] 9b bb [2] 87 bc [2] 9b 93 }

  condition:
    any of them
}