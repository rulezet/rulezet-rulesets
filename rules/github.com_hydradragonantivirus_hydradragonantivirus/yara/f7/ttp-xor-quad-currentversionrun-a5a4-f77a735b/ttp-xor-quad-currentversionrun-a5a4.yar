rule TTP_XOR_QUAD_CurrentVersionRun_a5a4 {
  strings:
    $key_a5a4 = { f6 cb [2] d2 c5 [2] f9 e9 [2] d7 cb [2] c3 d0 [2] cc ca [2] d2 d7 [2] d0 d6 [2] cb d0 [2] d7 d7 [2] cb f8 }

  condition:
    any of them
}