rule TTP_XOR_QUAD_CurrentVersionRun_26cf {
  strings:
    $key_26cf = { 75 a0 [2] 51 ae [2] 7a 82 [2] 54 a0 [2] 40 bb [2] 4f a1 [2] 51 bc [2] 53 bd [2] 48 bb [2] 54 bc [2] 48 93 }

  condition:
    any of them
}