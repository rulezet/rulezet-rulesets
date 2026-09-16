rule TTP_XOR_QUAD_CurrentVersionRun_0e8f {
  strings:
    $key_0e8f = { 5d e0 [2] 79 ee [2] 52 c2 [2] 7c e0 [2] 68 fb [2] 67 e1 [2] 79 fc [2] 7b fd [2] 60 fb [2] 7c fc [2] 60 d3 }

  condition:
    any of them
}