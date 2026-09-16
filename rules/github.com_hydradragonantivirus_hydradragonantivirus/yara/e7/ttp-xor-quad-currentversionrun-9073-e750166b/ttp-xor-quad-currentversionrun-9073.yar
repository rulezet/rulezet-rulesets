rule TTP_XOR_QUAD_CurrentVersionRun_9073 {
  strings:
    $key_9073 = { c3 1c [2] e7 12 [2] cc 3e [2] e2 1c [2] f6 07 [2] f9 1d [2] e7 00 [2] e5 01 [2] fe 07 [2] e2 00 [2] fe 2f }

  condition:
    any of them
}