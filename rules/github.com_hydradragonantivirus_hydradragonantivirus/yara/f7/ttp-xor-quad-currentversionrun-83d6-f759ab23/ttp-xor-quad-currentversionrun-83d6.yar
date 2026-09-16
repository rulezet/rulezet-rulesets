rule TTP_XOR_QUAD_CurrentVersionRun_83d6 {
  strings:
    $key_83d6 = { d0 b9 [2] f4 b7 [2] df 9b [2] f1 b9 [2] e5 a2 [2] ea b8 [2] f4 a5 [2] f6 a4 [2] ed a2 [2] f1 a5 [2] ed 8a }

  condition:
    any of them
}