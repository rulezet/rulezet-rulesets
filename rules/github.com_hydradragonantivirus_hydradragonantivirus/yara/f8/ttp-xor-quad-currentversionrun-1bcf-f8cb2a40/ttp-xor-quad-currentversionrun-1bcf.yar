rule TTP_XOR_QUAD_CurrentVersionRun_1bcf {
  strings:
    $key_1bcf = { 48 a0 [2] 6c ae [2] 47 82 [2] 69 a0 [2] 7d bb [2] 72 a1 [2] 6c bc [2] 6e bd [2] 75 bb [2] 69 bc [2] 75 93 }

  condition:
    any of them
}