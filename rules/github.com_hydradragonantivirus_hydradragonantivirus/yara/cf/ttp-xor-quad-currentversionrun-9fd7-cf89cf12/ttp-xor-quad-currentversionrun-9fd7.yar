rule TTP_XOR_QUAD_CurrentVersionRun_9fd7 {
  strings:
    $key_9fd7 = { cc b8 [2] e8 b6 [2] c3 9a [2] ed b8 [2] f9 a3 [2] f6 b9 [2] e8 a4 [2] ea a5 [2] f1 a3 [2] ed a4 [2] f1 8b }

  condition:
    any of them
}