rule TTP_XOR_QUAD_CurrentVersionRun_99ad {
  strings:
    $key_99ad = { ca c2 [2] ee cc [2] c5 e0 [2] eb c2 [2] ff d9 [2] f0 c3 [2] ee de [2] ec df [2] f7 d9 [2] eb de [2] f7 f1 }

  condition:
    any of them
}