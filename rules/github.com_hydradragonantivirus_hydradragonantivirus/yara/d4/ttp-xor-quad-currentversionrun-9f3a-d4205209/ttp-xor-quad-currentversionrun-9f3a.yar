rule TTP_XOR_QUAD_CurrentVersionRun_9f3a {
  strings:
    $key_9f3a = { cc 55 [2] e8 5b [2] c3 77 [2] ed 55 [2] f9 4e [2] f6 54 [2] e8 49 [2] ea 48 [2] f1 4e [2] ed 49 [2] f1 66 }

  condition:
    any of them
}