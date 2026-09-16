rule TTP_XOR_QUAD_CurrentVersionRun_9f16 {
  strings:
    $key_9f16 = { cc 79 [2] e8 77 [2] c3 5b [2] ed 79 [2] f9 62 [2] f6 78 [2] e8 65 [2] ea 64 [2] f1 62 [2] ed 65 [2] f1 4a }

  condition:
    any of them
}