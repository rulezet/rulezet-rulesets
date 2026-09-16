rule TTP_XOR_QUAD_CurrentVersionRun_9577 {
  strings:
    $key_9577 = { c6 18 [2] e2 16 [2] c9 3a [2] e7 18 [2] f3 03 [2] fc 19 [2] e2 04 [2] e0 05 [2] fb 03 [2] e7 04 [2] fb 2b }

  condition:
    any of them
}