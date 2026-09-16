rule TTP_XOR_QUAD_CurrentVersionRun_9774 {
  strings:
    $key_9774 = { c4 1b [2] e0 15 [2] cb 39 [2] e5 1b [2] f1 00 [2] fe 1a [2] e0 07 [2] e2 06 [2] f9 00 [2] e5 07 [2] f9 28 }

  condition:
    any of them
}