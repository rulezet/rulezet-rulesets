rule TTP_XOR_QUAD_CurrentVersionRun_9773 {
  strings:
    $key_9773 = { c4 1c [2] e0 12 [2] cb 3e [2] e5 1c [2] f1 07 [2] fe 1d [2] e0 00 [2] e2 01 [2] f9 07 [2] e5 00 [2] f9 2f }

  condition:
    any of them
}