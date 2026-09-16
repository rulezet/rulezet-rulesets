rule TTP_XOR_QUAD_CurrentVersionRun_9029 {
  strings:
    $key_9029 = { c3 46 [2] e7 48 [2] cc 64 [2] e2 46 [2] f6 5d [2] f9 47 [2] e7 5a [2] e5 5b [2] fe 5d [2] e2 5a [2] fe 75 }

  condition:
    any of them
}