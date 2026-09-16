rule TTP_XOR_QUAD_CurrentVersionRun_9062 {
  strings:
    $key_9062 = { c3 0d [2] e7 03 [2] cc 2f [2] e2 0d [2] f6 16 [2] f9 0c [2] e7 11 [2] e5 10 [2] fe 16 [2] e2 11 [2] fe 3e }

  condition:
    any of them
}