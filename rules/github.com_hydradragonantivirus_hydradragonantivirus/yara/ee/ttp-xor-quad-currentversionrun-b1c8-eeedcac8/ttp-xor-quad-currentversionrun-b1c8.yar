rule TTP_XOR_QUAD_CurrentVersionRun_b1c8 {
  strings:
    $key_b1c8 = { e2 a7 [2] c6 a9 [2] ed 85 [2] c3 a7 [2] d7 bc [2] d8 a6 [2] c6 bb [2] c4 ba [2] df bc [2] c3 bb [2] df 94 }

  condition:
    any of them
}