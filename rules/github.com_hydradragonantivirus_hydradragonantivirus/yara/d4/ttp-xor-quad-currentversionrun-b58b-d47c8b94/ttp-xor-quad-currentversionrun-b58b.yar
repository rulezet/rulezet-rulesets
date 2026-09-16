rule TTP_XOR_QUAD_CurrentVersionRun_b58b {
  strings:
    $key_b58b = { e6 e4 [2] c2 ea [2] e9 c6 [2] c7 e4 [2] d3 ff [2] dc e5 [2] c2 f8 [2] c0 f9 [2] db ff [2] c7 f8 [2] db d7 }

  condition:
    any of them
}