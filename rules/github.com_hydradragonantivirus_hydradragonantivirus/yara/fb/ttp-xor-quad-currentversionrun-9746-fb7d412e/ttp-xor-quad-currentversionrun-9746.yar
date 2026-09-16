rule TTP_XOR_QUAD_CurrentVersionRun_9746 {
  strings:
    $key_9746 = { c4 29 [2] e0 27 [2] cb 0b [2] e5 29 [2] f1 32 [2] fe 28 [2] e0 35 [2] e2 34 [2] f9 32 [2] e5 35 [2] f9 1a }

  condition:
    any of them
}