rule TTP_XOR_QUAD_CurrentVersionRun_9004 {
  strings:
    $key_9004 = { c3 6b [2] e7 65 [2] cc 49 [2] e2 6b [2] f6 70 [2] f9 6a [2] e7 77 [2] e5 76 [2] fe 70 [2] e2 77 [2] fe 58 }

  condition:
    any of them
}