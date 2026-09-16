rule TTP_XOR_QUAD_CurrentVersionRun_998f {
  strings:
    $key_998f = { ca e0 [2] ee ee [2] c5 c2 [2] eb e0 [2] ff fb [2] f0 e1 [2] ee fc [2] ec fd [2] f7 fb [2] eb fc [2] f7 d3 }

  condition:
    any of them
}