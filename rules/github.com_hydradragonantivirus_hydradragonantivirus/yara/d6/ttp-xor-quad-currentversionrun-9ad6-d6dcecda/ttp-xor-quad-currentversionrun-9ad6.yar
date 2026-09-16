rule TTP_XOR_QUAD_CurrentVersionRun_9ad6 {
  strings:
    $key_9ad6 = { c9 b9 [2] ed b7 [2] c6 9b [2] e8 b9 [2] fc a2 [2] f3 b8 [2] ed a5 [2] ef a4 [2] f4 a2 [2] e8 a5 [2] f4 8a }

  condition:
    any of them
}