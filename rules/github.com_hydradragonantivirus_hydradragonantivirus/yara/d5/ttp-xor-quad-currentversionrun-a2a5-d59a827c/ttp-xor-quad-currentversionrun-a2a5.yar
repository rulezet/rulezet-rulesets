rule TTP_XOR_QUAD_CurrentVersionRun_a2a5 {
  strings:
    $key_a2a5 = { f1 ca [2] d5 c4 [2] fe e8 [2] d0 ca [2] c4 d1 [2] cb cb [2] d5 d6 [2] d7 d7 [2] cc d1 [2] d0 d6 [2] cc f9 }

  condition:
    any of them
}