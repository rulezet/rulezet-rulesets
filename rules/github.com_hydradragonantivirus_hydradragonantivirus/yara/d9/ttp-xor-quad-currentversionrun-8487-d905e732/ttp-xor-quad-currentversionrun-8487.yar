rule TTP_XOR_QUAD_CurrentVersionRun_8487 {
  strings:
    $key_8487 = { d7 e8 [2] f3 e6 [2] d8 ca [2] f6 e8 [2] e2 f3 [2] ed e9 [2] f3 f4 [2] f1 f5 [2] ea f3 [2] f6 f4 [2] ea db }

  condition:
    any of them
}