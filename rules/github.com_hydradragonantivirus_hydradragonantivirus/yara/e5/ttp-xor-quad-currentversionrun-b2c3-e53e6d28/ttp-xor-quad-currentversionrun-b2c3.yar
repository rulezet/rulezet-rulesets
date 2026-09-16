rule TTP_XOR_QUAD_CurrentVersionRun_b2c3 {
  strings:
    $key_b2c3 = { e1 ac [2] c5 a2 [2] ee 8e [2] c0 ac [2] d4 b7 [2] db ad [2] c5 b0 [2] c7 b1 [2] dc b7 [2] c0 b0 [2] dc 9f }

  condition:
    any of them
}