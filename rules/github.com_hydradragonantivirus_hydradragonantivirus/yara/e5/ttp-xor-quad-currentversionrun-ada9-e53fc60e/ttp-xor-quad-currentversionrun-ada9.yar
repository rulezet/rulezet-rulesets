rule TTP_XOR_QUAD_CurrentVersionRun_ada9 {
  strings:
    $key_ada9 = { fe c6 [2] da c8 [2] f1 e4 [2] df c6 [2] cb dd [2] c4 c7 [2] da da [2] d8 db [2] c3 dd [2] df da [2] c3 f5 }

  condition:
    any of them
}