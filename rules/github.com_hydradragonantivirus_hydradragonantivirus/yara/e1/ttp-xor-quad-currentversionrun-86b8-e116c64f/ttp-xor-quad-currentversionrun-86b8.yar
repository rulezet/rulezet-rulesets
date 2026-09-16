rule TTP_XOR_QUAD_CurrentVersionRun_86b8 {
  strings:
    $key_86b8 = { d5 d7 [2] f1 d9 [2] da f5 [2] f4 d7 [2] e0 cc [2] ef d6 [2] f1 cb [2] f3 ca [2] e8 cc [2] f4 cb [2] e8 e4 }

  condition:
    any of them
}