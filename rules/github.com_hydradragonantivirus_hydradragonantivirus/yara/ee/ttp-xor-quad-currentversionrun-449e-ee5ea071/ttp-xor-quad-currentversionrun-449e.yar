rule TTP_XOR_QUAD_CurrentVersionRun_449e {
  strings:
    $key_449e = { 17 f1 [2] 33 ff [2] 18 d3 [2] 36 f1 [2] 22 ea [2] 2d f0 [2] 33 ed [2] 31 ec [2] 2a ea [2] 36 ed [2] 2a c2 }

  condition:
    any of them
}