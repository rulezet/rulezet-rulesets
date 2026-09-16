rule TTP_XOR_QUAD_CurrentVersionRun_89b8 {
  strings:
    $key_89b8 = { da d7 [2] fe d9 [2] d5 f5 [2] fb d7 [2] ef cc [2] e0 d6 [2] fe cb [2] fc ca [2] e7 cc [2] fb cb [2] e7 e4 }

  condition:
    any of them
}