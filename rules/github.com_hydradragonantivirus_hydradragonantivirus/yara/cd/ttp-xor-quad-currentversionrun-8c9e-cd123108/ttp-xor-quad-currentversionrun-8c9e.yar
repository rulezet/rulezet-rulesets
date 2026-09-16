rule TTP_XOR_QUAD_CurrentVersionRun_8c9e {
  strings:
    $key_8c9e = { df f1 [2] fb ff [2] d0 d3 [2] fe f1 [2] ea ea [2] e5 f0 [2] fb ed [2] f9 ec [2] e2 ea [2] fe ed [2] e2 c2 }

  condition:
    any of them
}