rule TTP_XOR_QUAD_CurrentVersionRun_9bc9 {
  strings:
    $key_9bc9 = { c8 a6 [2] ec a8 [2] c7 84 [2] e9 a6 [2] fd bd [2] f2 a7 [2] ec ba [2] ee bb [2] f5 bd [2] e9 ba [2] f5 95 }

  condition:
    any of them
}