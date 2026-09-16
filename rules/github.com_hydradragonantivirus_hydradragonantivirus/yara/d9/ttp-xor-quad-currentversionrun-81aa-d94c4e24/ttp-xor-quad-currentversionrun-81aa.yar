rule TTP_XOR_QUAD_CurrentVersionRun_81aa {
  strings:
    $key_81aa = { d2 c5 [2] f6 cb [2] dd e7 [2] f3 c5 [2] e7 de [2] e8 c4 [2] f6 d9 [2] f4 d8 [2] ef de [2] f3 d9 [2] ef f6 }

  condition:
    any of them
}