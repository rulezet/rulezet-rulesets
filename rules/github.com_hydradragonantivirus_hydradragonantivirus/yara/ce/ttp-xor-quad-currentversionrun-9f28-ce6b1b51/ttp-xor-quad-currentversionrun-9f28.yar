rule TTP_XOR_QUAD_CurrentVersionRun_9f28 {
  strings:
    $key_9f28 = { cc 47 [2] e8 49 [2] c3 65 [2] ed 47 [2] f9 5c [2] f6 46 [2] e8 5b [2] ea 5a [2] f1 5c [2] ed 5b [2] f1 74 }

  condition:
    any of them
}