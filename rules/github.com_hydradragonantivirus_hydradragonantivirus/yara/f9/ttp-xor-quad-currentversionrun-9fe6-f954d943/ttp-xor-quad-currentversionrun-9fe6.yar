rule TTP_XOR_QUAD_CurrentVersionRun_9fe6 {
  strings:
    $key_9fe6 = { cc 89 [2] e8 87 [2] c3 ab [2] ed 89 [2] f9 92 [2] f6 88 [2] e8 95 [2] ea 94 [2] f1 92 [2] ed 95 [2] f1 ba }

  condition:
    any of them
}