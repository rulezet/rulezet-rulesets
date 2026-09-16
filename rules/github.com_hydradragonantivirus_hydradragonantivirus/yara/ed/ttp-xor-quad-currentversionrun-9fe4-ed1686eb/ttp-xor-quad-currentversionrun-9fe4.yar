rule TTP_XOR_QUAD_CurrentVersionRun_9fe4 {
  strings:
    $key_9fe4 = { cc 8b [2] e8 85 [2] c3 a9 [2] ed 8b [2] f9 90 [2] f6 8a [2] e8 97 [2] ea 96 [2] f1 90 [2] ed 97 [2] f1 b8 }

  condition:
    any of them
}