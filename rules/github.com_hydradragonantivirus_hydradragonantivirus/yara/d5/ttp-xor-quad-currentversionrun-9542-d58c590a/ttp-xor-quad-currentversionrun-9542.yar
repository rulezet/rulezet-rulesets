rule TTP_XOR_QUAD_CurrentVersionRun_9542 {
  strings:
    $key_9542 = { c6 2d [2] e2 23 [2] c9 0f [2] e7 2d [2] f3 36 [2] fc 2c [2] e2 31 [2] e0 30 [2] fb 36 [2] e7 31 [2] fb 1e }

  condition:
    any of them
}