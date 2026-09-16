rule TTP_XOR_QUAD_CurrentVersionRun_b2b2 {
  strings:
    $key_b2b2 = { e1 dd [2] c5 d3 [2] ee ff [2] c0 dd [2] d4 c6 [2] db dc [2] c5 c1 [2] c7 c0 [2] dc c6 [2] c0 c1 [2] dc ee }

  condition:
    any of them
}