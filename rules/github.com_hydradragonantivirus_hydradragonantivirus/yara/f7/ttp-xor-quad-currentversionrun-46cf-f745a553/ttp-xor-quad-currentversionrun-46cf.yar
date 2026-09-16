rule TTP_XOR_QUAD_CurrentVersionRun_46cf {
  strings:
    $key_46cf = { 15 a0 [2] 31 ae [2] 1a 82 [2] 34 a0 [2] 20 bb [2] 2f a1 [2] 31 bc [2] 33 bd [2] 28 bb [2] 34 bc [2] 28 93 }

  condition:
    any of them
}