rule TTP_XOR_QUAD_CurrentVersionRun_9f61 {
  strings:
    $key_9f61 = { cc 0e [2] e8 00 [2] c3 2c [2] ed 0e [2] f9 15 [2] f6 0f [2] e8 12 [2] ea 13 [2] f1 15 [2] ed 12 [2] f1 3d }

  condition:
    any of them
}