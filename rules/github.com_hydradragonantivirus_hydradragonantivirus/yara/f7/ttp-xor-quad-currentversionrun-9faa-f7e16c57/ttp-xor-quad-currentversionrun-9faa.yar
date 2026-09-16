rule TTP_XOR_QUAD_CurrentVersionRun_9faa {
  strings:
    $key_9faa = { cc c5 [2] e8 cb [2] c3 e7 [2] ed c5 [2] f9 de [2] f6 c4 [2] e8 d9 [2] ea d8 [2] f1 de [2] ed d9 [2] f1 f6 }

  condition:
    any of them
}