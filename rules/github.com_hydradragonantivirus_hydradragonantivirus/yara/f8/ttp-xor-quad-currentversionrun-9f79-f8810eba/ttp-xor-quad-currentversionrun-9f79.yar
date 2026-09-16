rule TTP_XOR_QUAD_CurrentVersionRun_9f79 {
  strings:
    $key_9f79 = { cc 16 [2] e8 18 [2] c3 34 [2] ed 16 [2] f9 0d [2] f6 17 [2] e8 0a [2] ea 0b [2] f1 0d [2] ed 0a [2] f1 25 }

  condition:
    any of them
}