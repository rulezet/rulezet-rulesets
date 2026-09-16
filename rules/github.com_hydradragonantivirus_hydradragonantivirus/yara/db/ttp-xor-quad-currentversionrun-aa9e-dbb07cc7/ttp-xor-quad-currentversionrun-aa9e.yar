rule TTP_XOR_QUAD_CurrentVersionRun_aa9e {
  strings:
    $key_aa9e = { f9 f1 [2] dd ff [2] f6 d3 [2] d8 f1 [2] cc ea [2] c3 f0 [2] dd ed [2] df ec [2] c4 ea [2] d8 ed [2] c4 c2 }

  condition:
    any of them
}