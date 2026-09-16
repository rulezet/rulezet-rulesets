rule TTP_XOR_QUAD_CurrentVersionRun_9019 {
  strings:
    $key_9019 = { c3 76 [2] e7 78 [2] cc 54 [2] e2 76 [2] f6 6d [2] f9 77 [2] e7 6a [2] e5 6b [2] fe 6d [2] e2 6a [2] fe 45 }

  condition:
    any of them
}