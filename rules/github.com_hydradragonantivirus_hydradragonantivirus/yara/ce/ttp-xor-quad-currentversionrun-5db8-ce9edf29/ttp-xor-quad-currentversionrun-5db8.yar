rule TTP_XOR_QUAD_CurrentVersionRun_5db8 {
  strings:
    $key_5db8 = { 0e d7 [2] 2a d9 [2] 01 f5 [2] 2f d7 [2] 3b cc [2] 34 d6 [2] 2a cb [2] 28 ca [2] 33 cc [2] 2f cb [2] 33 e4 }

  condition:
    any of them
}