rule TTP_XOR_QUAD_CurrentVersionRun_ffc3 {
  strings:
    $key_ffc3 = { ac ac [2] 88 a2 [2] a3 8e [2] 8d ac [2] 99 b7 [2] 96 ad [2] 88 b0 [2] 8a b1 [2] 91 b7 [2] 8d b0 [2] 91 9f }

  condition:
    any of them
}