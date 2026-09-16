rule TTP_XOR_QUAD_CurrentVersionRun_85a9 {
  strings:
    $key_85a9 = { d6 c6 [2] f2 c8 [2] d9 e4 [2] f7 c6 [2] e3 dd [2] ec c7 [2] f2 da [2] f0 db [2] eb dd [2] f7 da [2] eb f5 }

  condition:
    any of them
}