rule TTP_XOR_QUAD_CurrentVersionRun_84a4 {
  strings:
    $key_84a4 = { d7 cb [2] f3 c5 [2] d8 e9 [2] f6 cb [2] e2 d0 [2] ed ca [2] f3 d7 [2] f1 d6 [2] ea d0 [2] f6 d7 [2] ea f8 }

  condition:
    any of them
}