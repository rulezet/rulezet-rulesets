rule TTP_XOR_QUAD_CurrentVersionRun_9543 {
  strings:
    $key_9543 = { c6 2c [2] e2 22 [2] c9 0e [2] e7 2c [2] f3 37 [2] fc 2d [2] e2 30 [2] e0 31 [2] fb 37 [2] e7 30 [2] fb 1f }

  condition:
    any of them
}