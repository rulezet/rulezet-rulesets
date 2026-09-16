rule TTP_XOR_QUAD_CurrentVersionRun_9738 {
  strings:
    $key_9738 = { c4 57 [2] e0 59 [2] cb 75 [2] e5 57 [2] f1 4c [2] fe 56 [2] e0 4b [2] e2 4a [2] f9 4c [2] e5 4b [2] f9 64 }

  condition:
    any of them
}