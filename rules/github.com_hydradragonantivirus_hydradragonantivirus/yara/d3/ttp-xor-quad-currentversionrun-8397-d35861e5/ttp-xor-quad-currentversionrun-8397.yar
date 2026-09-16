rule TTP_XOR_QUAD_CurrentVersionRun_8397 {
  strings:
    $key_8397 = { d0 f8 [2] f4 f6 [2] df da [2] f1 f8 [2] e5 e3 [2] ea f9 [2] f4 e4 [2] f6 e5 [2] ed e3 [2] f1 e4 [2] ed cb }

  condition:
    any of them
}