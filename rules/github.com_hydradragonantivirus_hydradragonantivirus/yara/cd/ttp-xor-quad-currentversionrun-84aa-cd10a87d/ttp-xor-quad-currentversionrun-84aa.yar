rule TTP_XOR_QUAD_CurrentVersionRun_84aa {
  strings:
    $key_84aa = { d7 c5 [2] f3 cb [2] d8 e7 [2] f6 c5 [2] e2 de [2] ed c4 [2] f3 d9 [2] f1 d8 [2] ea de [2] f6 d9 [2] ea f6 }

  condition:
    any of them
}