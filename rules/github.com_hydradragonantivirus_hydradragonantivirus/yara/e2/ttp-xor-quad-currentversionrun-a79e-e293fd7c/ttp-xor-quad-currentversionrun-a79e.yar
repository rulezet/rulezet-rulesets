rule TTP_XOR_QUAD_CurrentVersionRun_a79e {
  strings:
    $key_a79e = { f4 f1 [2] d0 ff [2] fb d3 [2] d5 f1 [2] c1 ea [2] ce f0 [2] d0 ed [2] d2 ec [2] c9 ea [2] d5 ed [2] c9 c2 }

  condition:
    any of them
}