rule TTP_XOR_QUAD_CurrentVersionRun_9f64 {
  strings:
    $key_9f64 = { cc 0b [2] e8 05 [2] c3 29 [2] ed 0b [2] f9 10 [2] f6 0a [2] e8 17 [2] ea 16 [2] f1 10 [2] ed 17 [2] f1 38 }

  condition:
    any of them
}