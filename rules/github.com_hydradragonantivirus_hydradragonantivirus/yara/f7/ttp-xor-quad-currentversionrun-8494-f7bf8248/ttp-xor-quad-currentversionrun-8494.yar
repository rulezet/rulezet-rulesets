rule TTP_XOR_QUAD_CurrentVersionRun_8494 {
  strings:
    $key_8494 = { d7 fb [2] f3 f5 [2] d8 d9 [2] f6 fb [2] e2 e0 [2] ed fa [2] f3 e7 [2] f1 e6 [2] ea e0 [2] f6 e7 [2] ea c8 }

  condition:
    any of them
}