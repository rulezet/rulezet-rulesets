rule TTP_XOR_QUAD_CurrentVersionRun_82a4 {
  strings:
    $key_82a4 = { d1 cb [2] f5 c5 [2] de e9 [2] f0 cb [2] e4 d0 [2] eb ca [2] f5 d7 [2] f7 d6 [2] ec d0 [2] f0 d7 [2] ec f8 }

  condition:
    any of them
}