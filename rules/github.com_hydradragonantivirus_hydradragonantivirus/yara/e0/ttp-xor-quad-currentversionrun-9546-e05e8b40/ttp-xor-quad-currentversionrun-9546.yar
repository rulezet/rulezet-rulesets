rule TTP_XOR_QUAD_CurrentVersionRun_9546 {
  strings:
    $key_9546 = { c6 29 [2] e2 27 [2] c9 0b [2] e7 29 [2] f3 32 [2] fc 28 [2] e2 35 [2] e0 34 [2] fb 32 [2] e7 35 [2] fb 1a }

  condition:
    any of them
}