rule TTP_XOR_QUAD_CurrentVersionRun_539e {
  strings:
    $key_539e = { 00 f1 [2] 24 ff [2] 0f d3 [2] 21 f1 [2] 35 ea [2] 3a f0 [2] 24 ed [2] 26 ec [2] 3d ea [2] 21 ed [2] 3d c2 }

  condition:
    any of them
}