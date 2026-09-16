rule TTP_XOR_QUAD_CurrentVersionRun_fdb8 {
  strings:
    $key_fdb8 = { ae d7 [2] 8a d9 [2] a1 f5 [2] 8f d7 [2] 9b cc [2] 94 d6 [2] 8a cb [2] 88 ca [2] 93 cc [2] 8f cb [2] 93 e4 }

  condition:
    any of them
}