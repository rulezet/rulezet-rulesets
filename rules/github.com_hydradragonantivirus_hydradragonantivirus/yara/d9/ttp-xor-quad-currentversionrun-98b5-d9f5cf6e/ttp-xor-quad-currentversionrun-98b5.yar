rule TTP_XOR_QUAD_CurrentVersionRun_98b5 {
  strings:
    $key_98b5 = { cb da [2] ef d4 [2] c4 f8 [2] ea da [2] fe c1 [2] f1 db [2] ef c6 [2] ed c7 [2] f6 c1 [2] ea c6 [2] f6 e9 }

  condition:
    any of them
}