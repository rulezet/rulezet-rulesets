rule TTP_XOR_QUAD_CurrentVersionRun_0c8f {
  strings:
    $key_0c8f = { 5f e0 [2] 7b ee [2] 50 c2 [2] 7e e0 [2] 6a fb [2] 65 e1 [2] 7b fc [2] 79 fd [2] 62 fb [2] 7e fc [2] 62 d3 }

  condition:
    any of them
}