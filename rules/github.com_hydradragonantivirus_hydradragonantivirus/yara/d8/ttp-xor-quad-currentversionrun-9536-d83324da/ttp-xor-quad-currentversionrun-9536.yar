rule TTP_XOR_QUAD_CurrentVersionRun_9536 {
  strings:
    $key_9536 = { c6 59 [2] e2 57 [2] c9 7b [2] e7 59 [2] f3 42 [2] fc 58 [2] e2 45 [2] e0 44 [2] fb 42 [2] e7 45 [2] fb 6a }

  condition:
    any of them
}