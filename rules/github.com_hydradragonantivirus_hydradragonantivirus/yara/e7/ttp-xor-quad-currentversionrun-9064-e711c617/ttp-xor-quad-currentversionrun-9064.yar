rule TTP_XOR_QUAD_CurrentVersionRun_9064 {
  strings:
    $key_9064 = { c3 0b [2] e7 05 [2] cc 29 [2] e2 0b [2] f6 10 [2] f9 0a [2] e7 17 [2] e5 16 [2] fe 10 [2] e2 17 [2] fe 38 }

  condition:
    any of them
}