rule TTP_XOR_QUAD_CurrentVersionRun_9ff3 {
  strings:
    $key_9ff3 = { cc 9c [2] e8 92 [2] c3 be [2] ed 9c [2] f9 87 [2] f6 9d [2] e8 80 [2] ea 81 [2] f1 87 [2] ed 80 [2] f1 af }

  condition:
    any of them
}