rule TTP_XOR_QUAD_CurrentVersionRun_9f04 {
  strings:
    $key_9f04 = { cc 6b [2] e8 65 [2] c3 49 [2] ed 6b [2] f9 70 [2] f6 6a [2] e8 77 [2] ea 76 [2] f1 70 [2] ed 77 [2] f1 58 }

  condition:
    any of them
}