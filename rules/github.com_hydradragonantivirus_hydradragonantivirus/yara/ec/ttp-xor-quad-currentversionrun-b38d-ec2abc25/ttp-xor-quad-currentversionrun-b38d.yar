rule TTP_XOR_QUAD_CurrentVersionRun_b38d {
  strings:
    $key_b38d = { e0 e2 [2] c4 ec [2] ef c0 [2] c1 e2 [2] d5 f9 [2] da e3 [2] c4 fe [2] c6 ff [2] dd f9 [2] c1 fe [2] dd d1 }

  condition:
    any of them
}