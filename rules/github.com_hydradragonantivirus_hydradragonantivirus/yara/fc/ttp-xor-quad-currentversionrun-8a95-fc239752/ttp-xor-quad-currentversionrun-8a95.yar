rule TTP_XOR_QUAD_CurrentVersionRun_8a95 {
  strings:
    $key_8a95 = { d9 fa [2] fd f4 [2] d6 d8 [2] f8 fa [2] ec e1 [2] e3 fb [2] fd e6 [2] ff e7 [2] e4 e1 [2] f8 e6 [2] e4 c9 }

  condition:
    any of them
}