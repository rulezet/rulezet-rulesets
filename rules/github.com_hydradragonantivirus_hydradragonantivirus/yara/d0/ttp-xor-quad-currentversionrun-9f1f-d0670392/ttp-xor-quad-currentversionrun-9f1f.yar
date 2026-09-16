rule TTP_XOR_QUAD_CurrentVersionRun_9f1f {
  strings:
    $key_9f1f = { cc 70 [2] e8 7e [2] c3 52 [2] ed 70 [2] f9 6b [2] f6 71 [2] e8 6c [2] ea 6d [2] f1 6b [2] ed 6c [2] f1 43 }

  condition:
    any of them
}