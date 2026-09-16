rule TTP_XOR_QUAD_CurrentVersionRun_1f9e {
  strings:
    $key_1f9e = { 4c f1 [2] 68 ff [2] 43 d3 [2] 6d f1 [2] 79 ea [2] 76 f0 [2] 68 ed [2] 6a ec [2] 71 ea [2] 6d ed [2] 71 c2 }

  condition:
    any of them
}