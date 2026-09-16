rule TTP_XOR_QUAD_CurrentVersionRun_969e {
  strings:
    $key_969e = { c5 f1 [2] e1 ff [2] ca d3 [2] e4 f1 [2] f0 ea [2] ff f0 [2] e1 ed [2] e3 ec [2] f8 ea [2] e4 ed [2] f8 c2 }

  condition:
    any of them
}