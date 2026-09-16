rule TTP_XOR_QUAD_CurrentVersionRun_c8df {
  strings:
    $key_c8df = { 9b b0 [2] bf be [2] 94 92 [2] ba b0 [2] ae ab [2] a1 b1 [2] bf ac [2] bd ad [2] a6 ab [2] ba ac [2] a6 83 }

  condition:
    any of them
}