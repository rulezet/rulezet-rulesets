rule TTP_XOR_QUAD_CurrentVersionRun_9f48 {
  strings:
    $key_9f48 = { cc 27 [2] e8 29 [2] c3 05 [2] ed 27 [2] f9 3c [2] f6 26 [2] e8 3b [2] ea 3a [2] f1 3c [2] ed 3b [2] f1 14 }

  condition:
    any of them
}