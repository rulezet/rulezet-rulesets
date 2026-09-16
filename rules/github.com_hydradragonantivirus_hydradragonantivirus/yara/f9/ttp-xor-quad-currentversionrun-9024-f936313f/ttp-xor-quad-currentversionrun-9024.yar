rule TTP_XOR_QUAD_CurrentVersionRun_9024 {
  strings:
    $key_9024 = { c3 4b [2] e7 45 [2] cc 69 [2] e2 4b [2] f6 50 [2] f9 4a [2] e7 57 [2] e5 56 [2] fe 50 [2] e2 57 [2] fe 78 }

  condition:
    any of them
}