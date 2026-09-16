rule TTP_XOR_QUAD_CurrentVersionRun_9aaa {
  strings:
    $key_9aaa = { c9 c5 [2] ed cb [2] c6 e7 [2] e8 c5 [2] fc de [2] f3 c4 [2] ed d9 [2] ef d8 [2] f4 de [2] e8 d9 [2] f4 f6 }

  condition:
    any of them
}