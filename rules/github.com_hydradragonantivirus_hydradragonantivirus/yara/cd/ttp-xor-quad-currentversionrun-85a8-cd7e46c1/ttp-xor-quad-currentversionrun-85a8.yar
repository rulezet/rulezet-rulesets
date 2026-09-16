rule TTP_XOR_QUAD_CurrentVersionRun_85a8 {
  strings:
    $key_85a8 = { d6 c7 [2] f2 c9 [2] d9 e5 [2] f7 c7 [2] e3 dc [2] ec c6 [2] f2 db [2] f0 da [2] eb dc [2] f7 db [2] eb f4 }

  condition:
    any of them
}