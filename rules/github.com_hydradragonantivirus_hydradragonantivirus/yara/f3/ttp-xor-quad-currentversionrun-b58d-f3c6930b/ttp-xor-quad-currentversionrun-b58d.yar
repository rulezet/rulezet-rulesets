rule TTP_XOR_QUAD_CurrentVersionRun_b58d {
  strings:
    $key_b58d = { e6 e2 [2] c2 ec [2] e9 c0 [2] c7 e2 [2] d3 f9 [2] dc e3 [2] c2 fe [2] c0 ff [2] db f9 [2] c7 fe [2] db d1 }

  condition:
    any of them
}