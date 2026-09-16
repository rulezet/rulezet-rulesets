rule TTP_XOR_QUAD_CurrentVersionRun_949e {
  strings:
    $key_949e = { c7 f1 [2] e3 ff [2] c8 d3 [2] e6 f1 [2] f2 ea [2] fd f0 [2] e3 ed [2] e1 ec [2] fa ea [2] e6 ed [2] fa c2 }

  condition:
    any of them
}