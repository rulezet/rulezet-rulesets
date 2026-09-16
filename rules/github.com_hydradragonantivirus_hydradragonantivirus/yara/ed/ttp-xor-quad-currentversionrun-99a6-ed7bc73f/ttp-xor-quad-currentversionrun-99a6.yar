rule TTP_XOR_QUAD_CurrentVersionRun_99a6 {
  strings:
    $key_99a6 = { ca c9 [2] ee c7 [2] c5 eb [2] eb c9 [2] ff d2 [2] f0 c8 [2] ee d5 [2] ec d4 [2] f7 d2 [2] eb d5 [2] f7 fa }

  condition:
    any of them
}