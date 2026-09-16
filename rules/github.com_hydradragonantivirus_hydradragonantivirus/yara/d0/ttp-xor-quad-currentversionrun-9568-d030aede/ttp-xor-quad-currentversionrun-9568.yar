rule TTP_XOR_QUAD_CurrentVersionRun_9568 {
  strings:
    $key_9568 = { c6 07 [2] e2 09 [2] c9 25 [2] e7 07 [2] f3 1c [2] fc 06 [2] e2 1b [2] e0 1a [2] fb 1c [2] e7 1b [2] fb 34 }

  condition:
    any of them
}