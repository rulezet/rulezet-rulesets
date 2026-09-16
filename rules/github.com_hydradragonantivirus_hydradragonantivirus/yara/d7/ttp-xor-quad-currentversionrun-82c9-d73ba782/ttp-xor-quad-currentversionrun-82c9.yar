rule TTP_XOR_QUAD_CurrentVersionRun_82c9 {
  strings:
    $key_82c9 = { d1 a6 [2] f5 a8 [2] de 84 [2] f0 a6 [2] e4 bd [2] eb a7 [2] f5 ba [2] f7 bb [2] ec bd [2] f0 ba [2] ec 95 }

  condition:
    any of them
}