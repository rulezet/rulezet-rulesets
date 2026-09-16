rule TTP_XOR_QUAD_CurrentVersionRun_42cf {
  strings:
    $key_42cf = { 11 a0 [2] 35 ae [2] 1e 82 [2] 30 a0 [2] 24 bb [2] 2b a1 [2] 35 bc [2] 37 bd [2] 2c bb [2] 30 bc [2] 2c 93 }

  condition:
    any of them
}