rule TTP_XOR_QUAD_CurrentVersionRun_9013 {
  strings:
    $key_9013 = { c3 7c [2] e7 72 [2] cc 5e [2] e2 7c [2] f6 67 [2] f9 7d [2] e7 60 [2] e5 61 [2] fe 67 [2] e2 60 [2] fe 4f }

  condition:
    any of them
}