rule TTP_XOR_QUAD_CurrentVersionRun_9007 {
  strings:
    $key_9007 = { c3 68 [2] e7 66 [2] cc 4a [2] e2 68 [2] f6 73 [2] f9 69 [2] e7 74 [2] e5 75 [2] fe 73 [2] e2 74 [2] fe 5b }

  condition:
    any of them
}