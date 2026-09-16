rule TTP_XOR_QUAD_CurrentVersionRun_9725 {
  strings:
    $key_9725 = { c4 4a [2] e0 44 [2] cb 68 [2] e5 4a [2] f1 51 [2] fe 4b [2] e0 56 [2] e2 57 [2] f9 51 [2] e5 56 [2] f9 79 }

  condition:
    any of them
}