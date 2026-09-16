rule TTP_XOR_QUAD_CurrentVersionRun_b5a5 {
  strings:
    $key_b5a5 = { e6 ca [2] c2 c4 [2] e9 e8 [2] c7 ca [2] d3 d1 [2] dc cb [2] c2 d6 [2] c0 d7 [2] db d1 [2] c7 d6 [2] db f9 }

  condition:
    any of them
}