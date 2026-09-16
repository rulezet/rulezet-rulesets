rule TTP_XOR_QUAD_CurrentVersionRun_998b {
  strings:
    $key_998b = { ca e4 [2] ee ea [2] c5 c6 [2] eb e4 [2] ff ff [2] f0 e5 [2] ee f8 [2] ec f9 [2] f7 ff [2] eb f8 [2] f7 d7 }

  condition:
    any of them
}