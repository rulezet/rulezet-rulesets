rule TTP_XOR_QUAD_CurrentVersionRun_9076 {
  strings:
    $key_9076 = { c3 19 [2] e7 17 [2] cc 3b [2] e2 19 [2] f6 02 [2] f9 18 [2] e7 05 [2] e5 04 [2] fe 02 [2] e2 05 [2] fe 2a }

  condition:
    any of them
}