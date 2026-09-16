rule TTP_XOR_QUAD_CurrentVersionRun_90b7 {
  strings:
    $key_90b7 = { c3 d8 [2] e7 d6 [2] cc fa [2] e2 d8 [2] f6 c3 [2] f9 d9 [2] e7 c4 [2] e5 c5 [2] fe c3 [2] e2 c4 [2] fe eb }

  condition:
    any of them
}