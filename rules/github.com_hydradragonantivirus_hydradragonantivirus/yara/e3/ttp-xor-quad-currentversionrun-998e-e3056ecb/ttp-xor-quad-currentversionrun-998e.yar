rule TTP_XOR_QUAD_CurrentVersionRun_998e {
  strings:
    $key_998e = { ca e1 [2] ee ef [2] c5 c3 [2] eb e1 [2] ff fa [2] f0 e0 [2] ee fd [2] ec fc [2] f7 fa [2] eb fd [2] f7 d2 }

  condition:
    any of them
}