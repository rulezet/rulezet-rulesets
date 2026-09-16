rule TTP_XOR_QUAD_CurrentVersionRun_1c8f {
  strings:
    $key_1c8f = { 4f e0 [2] 6b ee [2] 40 c2 [2] 6e e0 [2] 7a fb [2] 75 e1 [2] 6b fc [2] 69 fd [2] 72 fb [2] 6e fc [2] 72 d3 }

  condition:
    any of them
}