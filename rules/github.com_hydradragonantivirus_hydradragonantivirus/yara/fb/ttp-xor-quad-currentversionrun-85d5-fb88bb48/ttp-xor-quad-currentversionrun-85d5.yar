rule TTP_XOR_QUAD_CurrentVersionRun_85d5 {
  strings:
    $key_85d5 = { d6 ba [2] f2 b4 [2] d9 98 [2] f7 ba [2] e3 a1 [2] ec bb [2] f2 a6 [2] f0 a7 [2] eb a1 [2] f7 a6 [2] eb 89 }

  condition:
    any of them
}