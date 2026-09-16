rule TTP_XOR_QUAD_CurrentVersionRun_82b1 {
  strings:
    $key_82b1 = { d1 de [2] f5 d0 [2] de fc [2] f0 de [2] e4 c5 [2] eb df [2] f5 c2 [2] f7 c3 [2] ec c5 [2] f0 c2 [2] ec ed }

  condition:
    any of them
}