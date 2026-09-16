rule TTP_XOR_QUAD_CurrentVersionRun_47cf {
  strings:
    $key_47cf = { 14 a0 [2] 30 ae [2] 1b 82 [2] 35 a0 [2] 21 bb [2] 2e a1 [2] 30 bc [2] 32 bd [2] 29 bb [2] 35 bc [2] 29 93 }

  condition:
    any of them
}