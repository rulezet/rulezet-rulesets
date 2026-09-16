rule TTP_XOR_QUAD_CurrentVersionRun_9016 {
  strings:
    $key_9016 = { c3 79 [2] e7 77 [2] cc 5b [2] e2 79 [2] f6 62 [2] f9 78 [2] e7 65 [2] e5 64 [2] fe 62 [2] e2 65 [2] fe 4a }

  condition:
    any of them
}