rule TTP_XOR_QUAD_CurrentVersionRun_87b5 {
  strings:
    $key_87b5 = { d4 da [2] f0 d4 [2] db f8 [2] f5 da [2] e1 c1 [2] ee db [2] f0 c6 [2] f2 c7 [2] e9 c1 [2] f5 c6 [2] e9 e9 }

  condition:
    any of them
}