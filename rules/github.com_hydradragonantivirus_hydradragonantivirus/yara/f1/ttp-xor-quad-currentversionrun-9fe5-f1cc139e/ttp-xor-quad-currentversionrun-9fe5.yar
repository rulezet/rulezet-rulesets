rule TTP_XOR_QUAD_CurrentVersionRun_9fe5 {
  strings:
    $key_9fe5 = { cc 8a [2] e8 84 [2] c3 a8 [2] ed 8a [2] f9 91 [2] f6 8b [2] e8 96 [2] ea 97 [2] f1 91 [2] ed 96 [2] f1 b9 }

  condition:
    any of them
}