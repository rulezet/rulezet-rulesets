rule TTP_XOR_QUAD_CurrentVersionRun_9764 {
  strings:
    $key_9764 = { c4 0b [2] e0 05 [2] cb 29 [2] e5 0b [2] f1 10 [2] fe 0a [2] e0 17 [2] e2 16 [2] f9 10 [2] e5 17 [2] f9 38 }

  condition:
    any of them
}