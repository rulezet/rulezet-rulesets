rule TTP_XOR_QUAD_CurrentVersionRun_85d4 {
  strings:
    $key_85d4 = { d6 bb [2] f2 b5 [2] d9 99 [2] f7 bb [2] e3 a0 [2] ec ba [2] f2 a7 [2] f0 a6 [2] eb a0 [2] f7 a7 [2] eb 88 }

  condition:
    any of them
}