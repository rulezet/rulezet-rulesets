rule TTP_XOR_QUAD_CurrentVersionRun_9fc3 {
  strings:
    $key_9fc3 = { cc ac [2] e8 a2 [2] c3 8e [2] ed ac [2] f9 b7 [2] f6 ad [2] e8 b0 [2] ea b1 [2] f1 b7 [2] ed b0 [2] f1 9f }

  condition:
    any of them
}