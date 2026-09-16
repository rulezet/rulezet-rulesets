rule TTP_XOR_QUAD_CurrentVersionRun_7e8f {
  strings:
    $key_7e8f = { 2d e0 [2] 09 ee [2] 22 c2 [2] 0c e0 [2] 18 fb [2] 17 e1 [2] 09 fc [2] 0b fd [2] 10 fb [2] 0c fc [2] 10 d3 }

  condition:
    any of them
}