rule TTP_XOR_QUAD_CurrentVersionRun_84b8 {
  strings:
    $key_84b8 = { d7 d7 [2] f3 d9 [2] d8 f5 [2] f6 d7 [2] e2 cc [2] ed d6 [2] f3 cb [2] f1 ca [2] ea cc [2] f6 cb [2] ea e4 }

  condition:
    any of them
}