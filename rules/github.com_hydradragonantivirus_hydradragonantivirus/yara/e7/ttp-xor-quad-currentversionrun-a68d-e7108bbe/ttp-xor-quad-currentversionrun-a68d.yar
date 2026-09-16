rule TTP_XOR_QUAD_CurrentVersionRun_a68d {
  strings:
    $key_a68d = { f5 e2 [2] d1 ec [2] fa c0 [2] d4 e2 [2] c0 f9 [2] cf e3 [2] d1 fe [2] d3 ff [2] c8 f9 [2] d4 fe [2] c8 d1 }

  condition:
    any of them
}