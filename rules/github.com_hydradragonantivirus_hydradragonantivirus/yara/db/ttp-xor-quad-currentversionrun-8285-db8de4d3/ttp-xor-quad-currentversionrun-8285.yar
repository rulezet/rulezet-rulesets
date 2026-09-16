rule TTP_XOR_QUAD_CurrentVersionRun_8285 {
  strings:
    $key_8285 = { d1 ea [2] f5 e4 [2] de c8 [2] f0 ea [2] e4 f1 [2] eb eb [2] f5 f6 [2] f7 f7 [2] ec f1 [2] f0 f6 [2] ec d9 }

  condition:
    any of them
}