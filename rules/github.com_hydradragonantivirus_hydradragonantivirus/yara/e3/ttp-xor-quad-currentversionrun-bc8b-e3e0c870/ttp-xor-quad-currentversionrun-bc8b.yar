rule TTP_XOR_QUAD_CurrentVersionRun_bc8b {
  strings:
    $key_bc8b = { ef e4 [2] cb ea [2] e0 c6 [2] ce e4 [2] da ff [2] d5 e5 [2] cb f8 [2] c9 f9 [2] d2 ff [2] ce f8 [2] d2 d7 }

  condition:
    any of them
}