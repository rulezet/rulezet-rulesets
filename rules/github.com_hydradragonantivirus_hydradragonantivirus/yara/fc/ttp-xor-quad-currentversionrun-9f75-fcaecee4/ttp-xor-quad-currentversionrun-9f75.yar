rule TTP_XOR_QUAD_CurrentVersionRun_9f75 {
  strings:
    $key_9f75 = { cc 1a [2] e8 14 [2] c3 38 [2] ed 1a [2] f9 01 [2] f6 1b [2] e8 06 [2] ea 07 [2] f1 01 [2] ed 06 [2] f1 29 }

  condition:
    any of them
}