rule TTP_XOR_QUAD_CurrentVersionRun_9040 {
  strings:
    $key_9040 = { c3 2f [2] e7 21 [2] cc 0d [2] e2 2f [2] f6 34 [2] f9 2e [2] e7 33 [2] e5 32 [2] fe 34 [2] e2 33 [2] fe 1c }

  condition:
    any of them
}