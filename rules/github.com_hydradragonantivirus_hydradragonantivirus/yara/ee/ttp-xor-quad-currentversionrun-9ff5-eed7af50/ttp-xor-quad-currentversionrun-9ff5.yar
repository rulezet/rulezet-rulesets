rule TTP_XOR_QUAD_CurrentVersionRun_9ff5 {
  strings:
    $key_9ff5 = { cc 9a [2] e8 94 [2] c3 b8 [2] ed 9a [2] f9 81 [2] f6 9b [2] e8 86 [2] ea 87 [2] f1 81 [2] ed 86 [2] f1 a9 }

  condition:
    any of them
}