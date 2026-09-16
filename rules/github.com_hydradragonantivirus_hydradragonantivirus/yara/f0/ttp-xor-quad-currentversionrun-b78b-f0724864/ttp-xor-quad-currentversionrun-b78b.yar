rule TTP_XOR_QUAD_CurrentVersionRun_b78b {
  strings:
    $key_b78b = { e4 e4 [2] c0 ea [2] eb c6 [2] c5 e4 [2] d1 ff [2] de e5 [2] c0 f8 [2] c2 f9 [2] d9 ff [2] c5 f8 [2] d9 d7 }

  condition:
    any of them
}