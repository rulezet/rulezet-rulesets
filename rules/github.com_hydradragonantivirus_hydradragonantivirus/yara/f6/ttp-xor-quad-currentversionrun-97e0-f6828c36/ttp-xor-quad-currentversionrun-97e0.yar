rule TTP_XOR_QUAD_CurrentVersionRun_97e0 {
  strings:
    $key_97e0 = { c4 8f [2] e0 81 [2] cb ad [2] e5 8f [2] f1 94 [2] fe 8e [2] e0 93 [2] e2 92 [2] f9 94 [2] e5 93 [2] f9 bc }

  condition:
    any of them
}