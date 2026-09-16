rule TTP_XOR_QUAD_CurrentVersionRun_85c6 {
  strings:
    $key_85c6 = { d6 a9 [2] f2 a7 [2] d9 8b [2] f7 a9 [2] e3 b2 [2] ec a8 [2] f2 b5 [2] f0 b4 [2] eb b2 [2] f7 b5 [2] eb 9a }

  condition:
    any of them
}