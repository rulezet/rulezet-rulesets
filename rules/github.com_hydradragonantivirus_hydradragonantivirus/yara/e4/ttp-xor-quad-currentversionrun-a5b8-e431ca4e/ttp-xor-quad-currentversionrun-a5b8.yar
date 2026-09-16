rule TTP_XOR_QUAD_CurrentVersionRun_a5b8 {
  strings:
    $key_a5b8 = { f6 d7 [2] d2 d9 [2] f9 f5 [2] d7 d7 [2] c3 cc [2] cc d6 [2] d2 cb [2] d0 ca [2] cb cc [2] d7 cb [2] cb e4 }

  condition:
    any of them
}