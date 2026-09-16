rule TTP_XOR_QUAD_CurrentVersionRun_9fd6 {
  strings:
    $key_9fd6 = { cc b9 [2] e8 b7 [2] c3 9b [2] ed b9 [2] f9 a2 [2] f6 b8 [2] e8 a5 [2] ea a4 [2] f1 a2 [2] ed a5 [2] f1 8a }

  condition:
    any of them
}