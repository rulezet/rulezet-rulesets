rule TTP_XOR_QUAD_CurrentVersionRun_81bf {
  strings:
    $key_81bf = { d2 d0 [2] f6 de [2] dd f2 [2] f3 d0 [2] e7 cb [2] e8 d1 [2] f6 cc [2] f4 cd [2] ef cb [2] f3 cc [2] ef e3 }

  condition:
    any of them
}