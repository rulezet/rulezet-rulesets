rule TTP_XOR_QUAD_CurrentVersionRun_9729 {
  strings:
    $key_9729 = { c4 46 [2] e0 48 [2] cb 64 [2] e5 46 [2] f1 5d [2] fe 47 [2] e0 5a [2] e2 5b [2] f9 5d [2] e5 5a [2] f9 75 }

  condition:
    any of them
}