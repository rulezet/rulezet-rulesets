rule TTP_XOR_QUAD_CurrentVersionRun_99dd {
  strings:
    $key_99dd = { ca b2 [2] ee bc [2] c5 90 [2] eb b2 [2] ff a9 [2] f0 b3 [2] ee ae [2] ec af [2] f7 a9 [2] eb ae [2] f7 81 }

  condition:
    any of them
}