rule TTP_XOR_QUAD_CurrentVersionRun_9740 {
  strings:
    $key_9740 = { c4 2f [2] e0 21 [2] cb 0d [2] e5 2f [2] f1 34 [2] fe 2e [2] e0 33 [2] e2 32 [2] f9 34 [2] e5 33 [2] f9 1c }

  condition:
    any of them
}