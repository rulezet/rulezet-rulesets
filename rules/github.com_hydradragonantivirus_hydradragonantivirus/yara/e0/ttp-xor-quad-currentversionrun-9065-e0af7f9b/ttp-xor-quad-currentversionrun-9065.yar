rule TTP_XOR_QUAD_CurrentVersionRun_9065 {
  strings:
    $key_9065 = { c3 0a [2] e7 04 [2] cc 28 [2] e2 0a [2] f6 11 [2] f9 0b [2] e7 16 [2] e5 17 [2] fe 11 [2] e2 16 [2] fe 39 }

  condition:
    any of them
}