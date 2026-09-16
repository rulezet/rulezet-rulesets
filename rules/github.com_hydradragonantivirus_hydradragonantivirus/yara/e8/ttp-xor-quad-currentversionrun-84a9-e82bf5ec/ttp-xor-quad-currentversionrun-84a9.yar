rule TTP_XOR_QUAD_CurrentVersionRun_84a9 {
  strings:
    $key_84a9 = { d7 c6 [2] f3 c8 [2] d8 e4 [2] f6 c6 [2] e2 dd [2] ed c7 [2] f3 da [2] f1 db [2] ea dd [2] f6 da [2] ea f5 }

  condition:
    any of them
}