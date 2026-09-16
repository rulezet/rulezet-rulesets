rule TTP_XOR_QUAD_CurrentVersionRun_b7a5 {
  strings:
    $key_b7a5 = { e4 ca [2] c0 c4 [2] eb e8 [2] c5 ca [2] d1 d1 [2] de cb [2] c0 d6 [2] c2 d7 [2] d9 d1 [2] c5 d6 [2] d9 f9 }

  condition:
    any of them
}