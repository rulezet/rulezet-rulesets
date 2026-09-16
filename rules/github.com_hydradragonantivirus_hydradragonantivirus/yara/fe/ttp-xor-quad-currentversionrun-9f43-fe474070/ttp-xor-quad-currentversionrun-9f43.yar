rule TTP_XOR_QUAD_CurrentVersionRun_9f43 {
  strings:
    $key_9f43 = { cc 2c [2] e8 22 [2] c3 0e [2] ed 2c [2] f9 37 [2] f6 2d [2] e8 30 [2] ea 31 [2] f1 37 [2] ed 30 [2] f1 1f }

  condition:
    any of them
}