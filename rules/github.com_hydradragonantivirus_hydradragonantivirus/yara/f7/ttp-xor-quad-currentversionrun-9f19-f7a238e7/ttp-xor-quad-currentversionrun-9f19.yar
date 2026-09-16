rule TTP_XOR_QUAD_CurrentVersionRun_9f19 {
  strings:
    $key_9f19 = { cc 76 [2] e8 78 [2] c3 54 [2] ed 76 [2] f9 6d [2] f6 77 [2] e8 6a [2] ea 6b [2] f1 6d [2] ed 6a [2] f1 45 }

  condition:
    any of them
}