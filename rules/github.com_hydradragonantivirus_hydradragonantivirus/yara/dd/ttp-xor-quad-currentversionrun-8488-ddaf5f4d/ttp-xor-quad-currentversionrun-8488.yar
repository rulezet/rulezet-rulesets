rule TTP_XOR_QUAD_CurrentVersionRun_8488 {
  strings:
    $key_8488 = { d7 e7 [2] f3 e9 [2] d8 c5 [2] f6 e7 [2] e2 fc [2] ed e6 [2] f3 fb [2] f1 fa [2] ea fc [2] f6 fb [2] ea d4 }

  condition:
    any of them
}