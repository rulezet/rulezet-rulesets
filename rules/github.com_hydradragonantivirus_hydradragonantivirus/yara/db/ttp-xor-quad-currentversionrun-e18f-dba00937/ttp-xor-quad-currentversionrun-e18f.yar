rule TTP_XOR_QUAD_CurrentVersionRun_e18f {
  strings:
    $key_e18f = { b2 e0 [2] 96 ee [2] bd c2 [2] 93 e0 [2] 87 fb [2] 88 e1 [2] 96 fc [2] 94 fd [2] 8f fb [2] 93 fc [2] 8f d3 }

  condition:
    any of them
}