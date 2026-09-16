rule TTP_XOR_QUAD_CurrentVersionRun_f1c3 {
  strings:
    $key_f1c3 = { a2 ac [2] 86 a2 [2] ad 8e [2] 83 ac [2] 97 b7 [2] 98 ad [2] 86 b0 [2] 84 b1 [2] 9f b7 [2] 83 b0 [2] 9f 9f }

  condition:
    any of them
}