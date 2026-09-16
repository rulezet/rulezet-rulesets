rule TTP_XOR_QUAD_CurrentVersionRun_9058 {
  strings:
    $key_9058 = { c3 37 [2] e7 39 [2] cc 15 [2] e2 37 [2] f6 2c [2] f9 36 [2] e7 2b [2] e5 2a [2] fe 2c [2] e2 2b [2] fe 04 }

  condition:
    any of them
}