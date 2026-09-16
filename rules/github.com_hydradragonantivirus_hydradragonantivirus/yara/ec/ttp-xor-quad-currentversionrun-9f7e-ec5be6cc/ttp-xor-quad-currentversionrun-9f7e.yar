rule TTP_XOR_QUAD_CurrentVersionRun_9f7e {
  strings:
    $key_9f7e = { cc 11 [2] e8 1f [2] c3 33 [2] ed 11 [2] f9 0a [2] f6 10 [2] e8 0d [2] ea 0c [2] f1 0a [2] ed 0d [2] f1 22 }

  condition:
    any of them
}