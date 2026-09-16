rule TTP_XOR_QUAD_CurrentVersionRun_9575 {
  strings:
    $key_9575 = { c6 1a [2] e2 14 [2] c9 38 [2] e7 1a [2] f3 01 [2] fc 1b [2] e2 06 [2] e0 07 [2] fb 01 [2] e7 06 [2] fb 29 }

  condition:
    any of them
}