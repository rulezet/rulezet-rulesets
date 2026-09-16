rule TTP_XOR_QUAD_CurrentVersionRun_9f49 {
  strings:
    $key_9f49 = { cc 26 [2] e8 28 [2] c3 04 [2] ed 26 [2] f9 3d [2] f6 27 [2] e8 3a [2] ea 3b [2] f1 3d [2] ed 3a [2] f1 15 }

  condition:
    any of them
}