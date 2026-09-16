rule TTP_XOR_QUAD_CurrentVersionRun_9715 {
  strings:
    $key_9715 = { c4 7a [2] e0 74 [2] cb 58 [2] e5 7a [2] f1 61 [2] fe 7b [2] e0 66 [2] e2 67 [2] f9 61 [2] e5 66 [2] f9 49 }

  condition:
    any of them
}