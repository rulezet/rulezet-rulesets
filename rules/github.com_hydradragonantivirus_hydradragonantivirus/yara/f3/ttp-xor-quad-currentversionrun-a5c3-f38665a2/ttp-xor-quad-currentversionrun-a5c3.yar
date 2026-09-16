rule TTP_XOR_QUAD_CurrentVersionRun_a5c3 {
  strings:
    $key_a5c3 = { f6 ac [2] d2 a2 [2] f9 8e [2] d7 ac [2] c3 b7 [2] cc ad [2] d2 b0 [2] d0 b1 [2] cb b7 [2] d7 b0 [2] cb 9f }

  condition:
    any of them
}