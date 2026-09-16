rule TTP_XOR_QUAD_CurrentVersionRun_998a {
  strings:
    $key_998a = { ca e5 [2] ee eb [2] c5 c7 [2] eb e5 [2] ff fe [2] f0 e4 [2] ee f9 [2] ec f8 [2] f7 fe [2] eb f9 [2] f7 d6 }

  condition:
    any of them
}