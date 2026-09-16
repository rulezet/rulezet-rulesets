rule TTP_XOR_QUAD_CurrentVersionRun_9516 {
  strings:
    $key_9516 = { c6 79 [2] e2 77 [2] c9 5b [2] e7 79 [2] f3 62 [2] fc 78 [2] e2 65 [2] e0 64 [2] fb 62 [2] e7 65 [2] fb 4a }

  condition:
    any of them
}