rule TTP_XOR_QUAD_CurrentVersionRun_8d9e {
  strings:
    $key_8d9e = { de f1 [2] fa ff [2] d1 d3 [2] ff f1 [2] eb ea [2] e4 f0 [2] fa ed [2] f8 ec [2] e3 ea [2] ff ed [2] e3 c2 }

  condition:
    any of them
}