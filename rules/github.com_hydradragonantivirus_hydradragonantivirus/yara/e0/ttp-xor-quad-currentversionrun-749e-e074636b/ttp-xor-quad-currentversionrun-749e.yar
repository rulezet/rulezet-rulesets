rule TTP_XOR_QUAD_CurrentVersionRun_749e {
  strings:
    $key_749e = { 27 f1 [2] 03 ff [2] 28 d3 [2] 06 f1 [2] 12 ea [2] 1d f0 [2] 03 ed [2] 01 ec [2] 1a ea [2] 06 ed [2] 1a c2 }

  condition:
    any of them
}