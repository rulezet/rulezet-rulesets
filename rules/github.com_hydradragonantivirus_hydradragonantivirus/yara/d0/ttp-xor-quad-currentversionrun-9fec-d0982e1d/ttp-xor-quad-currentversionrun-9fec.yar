rule TTP_XOR_QUAD_CurrentVersionRun_9fec {
  strings:
    $key_9fec = { cc 83 [2] e8 8d [2] c3 a1 [2] ed 83 [2] f9 98 [2] f6 82 [2] e8 9f [2] ea 9e [2] f1 98 [2] ed 9f [2] f1 b0 }

  condition:
    any of them
}