rule TTP_XOR_QUAD_CurrentVersionRun_5d8f {
  strings:
    $key_5d8f = { 0e e0 [2] 2a ee [2] 01 c2 [2] 2f e0 [2] 3b fb [2] 34 e1 [2] 2a fc [2] 28 fd [2] 33 fb [2] 2f fc [2] 33 d3 }

  condition:
    any of them
}