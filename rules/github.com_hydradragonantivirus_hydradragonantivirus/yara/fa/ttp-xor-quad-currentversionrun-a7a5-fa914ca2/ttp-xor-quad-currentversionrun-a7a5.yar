rule TTP_XOR_QUAD_CurrentVersionRun_a7a5 {
  strings:
    $key_a7a5 = { f4 ca [2] d0 c4 [2] fb e8 [2] d5 ca [2] c1 d1 [2] ce cb [2] d0 d6 [2] d2 d7 [2] c9 d1 [2] d5 d6 [2] c9 f9 }

  condition:
    any of them
}