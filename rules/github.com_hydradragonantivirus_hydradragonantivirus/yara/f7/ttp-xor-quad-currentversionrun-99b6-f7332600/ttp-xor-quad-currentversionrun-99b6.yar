rule TTP_XOR_QUAD_CurrentVersionRun_99b6 {
  strings:
    $key_99b6 = { ca d9 [2] ee d7 [2] c5 fb [2] eb d9 [2] ff c2 [2] f0 d8 [2] ee c5 [2] ec c4 [2] f7 c2 [2] eb c5 [2] f7 ea }

  condition:
    any of them
}