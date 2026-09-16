rule TTP_XOR_QUAD_CurrentVersionRun_9559 {
  strings:
    $key_9559 = { c6 36 [2] e2 38 [2] c9 14 [2] e7 36 [2] f3 2d [2] fc 37 [2] e2 2a [2] e0 2b [2] fb 2d [2] e7 2a [2] fb 05 }

  condition:
    any of them
}