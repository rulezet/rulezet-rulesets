rule TTP_XOR_QUAD_CurrentVersionRun_949a {
  strings:
    $key_949a = { c7 f5 [2] e3 fb [2] c8 d7 [2] e6 f5 [2] f2 ee [2] fd f4 [2] e3 e9 [2] e1 e8 [2] fa ee [2] e6 e9 [2] fa c6 }

  condition:
    any of them
}