rule TTP_XOR_QUAD_CurrentVersionRun_b48f {
  strings:
    $key_b48f = { e7 e0 [2] c3 ee [2] e8 c2 [2] c6 e0 [2] d2 fb [2] dd e1 [2] c3 fc [2] c1 fd [2] da fb [2] c6 fc [2] da d3 }

  condition:
    any of them
}