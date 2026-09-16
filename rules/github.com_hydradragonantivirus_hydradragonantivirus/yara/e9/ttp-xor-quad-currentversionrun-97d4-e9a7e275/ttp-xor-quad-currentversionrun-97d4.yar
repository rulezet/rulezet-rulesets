rule TTP_XOR_QUAD_CurrentVersionRun_97d4 {
  strings:
    $key_97d4 = { c4 bb [2] e0 b5 [2] cb 99 [2] e5 bb [2] f1 a0 [2] fe ba [2] e0 a7 [2] e2 a6 [2] f9 a0 [2] e5 a7 [2] f9 88 }

  condition:
    any of them
}