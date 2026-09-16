rule TTP_XOR_QUAD_CurrentVersionRun_9f69 {
  strings:
    $key_9f69 = { cc 06 [2] e8 08 [2] c3 24 [2] ed 06 [2] f9 1d [2] f6 07 [2] e8 1a [2] ea 1b [2] f1 1d [2] ed 1a [2] f1 35 }

  condition:
    any of them
}