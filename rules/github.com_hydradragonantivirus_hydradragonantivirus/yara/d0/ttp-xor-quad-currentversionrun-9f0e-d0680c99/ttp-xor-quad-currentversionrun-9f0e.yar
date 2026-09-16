rule TTP_XOR_QUAD_CurrentVersionRun_9f0e {
  strings:
    $key_9f0e = { cc 61 [2] e8 6f [2] c3 43 [2] ed 61 [2] f9 7a [2] f6 60 [2] e8 7d [2] ea 7c [2] f1 7a [2] ed 7d [2] f1 52 }

  condition:
    any of them
}