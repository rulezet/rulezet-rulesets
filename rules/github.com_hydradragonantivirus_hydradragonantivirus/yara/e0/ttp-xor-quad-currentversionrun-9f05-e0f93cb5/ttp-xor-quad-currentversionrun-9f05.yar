rule TTP_XOR_QUAD_CurrentVersionRun_9f05 {
  strings:
    $key_9f05 = { cc 6a [2] e8 64 [2] c3 48 [2] ed 6a [2] f9 71 [2] f6 6b [2] e8 76 [2] ea 77 [2] f1 71 [2] ed 76 [2] f1 59 }

  condition:
    any of them
}