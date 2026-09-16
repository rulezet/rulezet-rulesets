rule TTP_XOR_QUAD_CurrentVersionRun_9f65 {
  strings:
    $key_9f65 = { cc 0a [2] e8 04 [2] c3 28 [2] ed 0a [2] f9 11 [2] f6 0b [2] e8 16 [2] ea 17 [2] f1 11 [2] ed 16 [2] f1 39 }

  condition:
    any of them
}