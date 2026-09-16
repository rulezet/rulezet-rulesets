rule TTP_XOR_QUAD_CurrentVersionRun_9028 {
  strings:
    $key_9028 = { c3 47 [2] e7 49 [2] cc 65 [2] e2 47 [2] f6 5c [2] f9 46 [2] e7 5b [2] e5 5a [2] fe 5c [2] e2 5b [2] fe 74 }

  condition:
    any of them
}