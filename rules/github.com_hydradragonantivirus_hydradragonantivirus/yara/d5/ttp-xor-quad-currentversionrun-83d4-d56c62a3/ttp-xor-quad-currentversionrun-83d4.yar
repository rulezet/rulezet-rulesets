rule TTP_XOR_QUAD_CurrentVersionRun_83d4 {
  strings:
    $key_83d4 = { d0 bb [2] f4 b5 [2] df 99 [2] f1 bb [2] e5 a0 [2] ea ba [2] f4 a7 [2] f6 a6 [2] ed a0 [2] f1 a7 [2] ed 88 }

  condition:
    any of them
}