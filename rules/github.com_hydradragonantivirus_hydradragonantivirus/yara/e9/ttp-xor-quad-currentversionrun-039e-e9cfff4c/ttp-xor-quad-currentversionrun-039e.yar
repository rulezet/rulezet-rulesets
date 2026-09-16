rule TTP_XOR_QUAD_CurrentVersionRun_039e {
  strings:
    $key_039e = { 50 f1 [2] 74 ff [2] 5f d3 [2] 71 f1 [2] 65 ea [2] 6a f0 [2] 74 ed [2] 76 ec [2] 6d ea [2] 71 ed [2] 6d c2 }

  condition:
    any of them
}