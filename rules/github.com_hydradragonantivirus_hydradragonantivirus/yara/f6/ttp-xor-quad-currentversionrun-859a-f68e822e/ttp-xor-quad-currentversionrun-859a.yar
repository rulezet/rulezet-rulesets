rule TTP_XOR_QUAD_CurrentVersionRun_859a {
  strings:
    $key_859a = { d6 f5 [2] f2 fb [2] d9 d7 [2] f7 f5 [2] e3 ee [2] ec f4 [2] f2 e9 [2] f0 e8 [2] eb ee [2] f7 e9 [2] eb c6 }

  condition:
    any of them
}