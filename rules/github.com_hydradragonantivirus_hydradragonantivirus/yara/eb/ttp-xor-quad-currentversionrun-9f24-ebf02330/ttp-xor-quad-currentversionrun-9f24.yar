rule TTP_XOR_QUAD_CurrentVersionRun_9f24 {
  strings:
    $key_9f24 = { cc 4b [2] e8 45 [2] c3 69 [2] ed 4b [2] f9 50 [2] f6 4a [2] e8 57 [2] ea 56 [2] f1 50 [2] ed 57 [2] f1 78 }

  condition:
    any of them
}