rule TTP_XOR_QUAD_CurrentVersionRun_9051 {
  strings:
    $key_9051 = { c3 3e [2] e7 30 [2] cc 1c [2] e2 3e [2] f6 25 [2] f9 3f [2] e7 22 [2] e5 23 [2] fe 25 [2] e2 22 [2] fe 0d }

  condition:
    any of them
}