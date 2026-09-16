rule TTP_XOR_QUAD_CurrentVersionRun_b9c3 {
  strings:
    $key_b9c3 = { ea ac [2] ce a2 [2] e5 8e [2] cb ac [2] df b7 [2] d0 ad [2] ce b0 [2] cc b1 [2] d7 b7 [2] cb b0 [2] d7 9f }

  condition:
    any of them
}