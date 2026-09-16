rule TTP_XOR_QUAD_CurrentVersionRun_999e {
  strings:
    $key_999e = { ca f1 [2] ee ff [2] c5 d3 [2] eb f1 [2] ff ea [2] f0 f0 [2] ee ed [2] ec ec [2] f7 ea [2] eb ed [2] f7 c2 }

  condition:
    any of them
}