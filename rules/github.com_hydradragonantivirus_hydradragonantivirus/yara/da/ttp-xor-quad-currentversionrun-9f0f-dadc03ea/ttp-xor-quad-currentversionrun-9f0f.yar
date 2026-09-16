rule TTP_XOR_QUAD_CurrentVersionRun_9f0f {
  strings:
    $key_9f0f = { cc 60 [2] e8 6e [2] c3 42 [2] ed 60 [2] f9 7b [2] f6 61 [2] e8 7c [2] ea 7d [2] f1 7b [2] ed 7c [2] f1 53 }

  condition:
    any of them
}