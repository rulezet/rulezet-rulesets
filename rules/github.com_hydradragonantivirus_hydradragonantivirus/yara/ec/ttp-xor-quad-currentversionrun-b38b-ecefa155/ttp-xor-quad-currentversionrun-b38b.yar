rule TTP_XOR_QUAD_CurrentVersionRun_b38b {
  strings:
    $key_b38b = { e0 e4 [2] c4 ea [2] ef c6 [2] c1 e4 [2] d5 ff [2] da e5 [2] c4 f8 [2] c6 f9 [2] dd ff [2] c1 f8 [2] dd d7 }

  condition:
    any of them
}