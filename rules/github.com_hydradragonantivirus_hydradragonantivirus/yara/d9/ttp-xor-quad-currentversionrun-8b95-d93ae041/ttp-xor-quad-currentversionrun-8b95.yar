rule TTP_XOR_QUAD_CurrentVersionRun_8b95 {
  strings:
    $key_8b95 = { d8 fa [2] fc f4 [2] d7 d8 [2] f9 fa [2] ed e1 [2] e2 fb [2] fc e6 [2] fe e7 [2] e5 e1 [2] f9 e6 [2] e5 c9 }

  condition:
    any of them
}