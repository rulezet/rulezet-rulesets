rule TTP_XOR_QUAD_CurrentVersionRun_84d4 {
  strings:
    $key_84d4 = { d7 bb [2] f3 b5 [2] d8 99 [2] f6 bb [2] e2 a0 [2] ed ba [2] f3 a7 [2] f1 a6 [2] ea a0 [2] f6 a7 [2] ea 88 }

  condition:
    any of them
}