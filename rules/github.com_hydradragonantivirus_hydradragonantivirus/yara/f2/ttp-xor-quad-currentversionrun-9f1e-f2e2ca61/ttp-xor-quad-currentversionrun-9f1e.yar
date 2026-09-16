rule TTP_XOR_QUAD_CurrentVersionRun_9f1e {
  strings:
    $key_9f1e = { cc 71 [2] e8 7f [2] c3 53 [2] ed 71 [2] f9 6a [2] f6 70 [2] e8 6d [2] ea 6c [2] f1 6a [2] ed 6d [2] f1 42 }

  condition:
    any of them
}