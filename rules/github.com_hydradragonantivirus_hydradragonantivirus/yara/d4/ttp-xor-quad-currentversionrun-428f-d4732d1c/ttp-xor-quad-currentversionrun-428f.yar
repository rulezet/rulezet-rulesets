rule TTP_XOR_QUAD_CurrentVersionRun_428f {
  strings:
    $key_428f = { 11 e0 [2] 35 ee [2] 1e c2 [2] 30 e0 [2] 24 fb [2] 2b e1 [2] 35 fc [2] 37 fd [2] 2c fb [2] 30 fc [2] 2c d3 }

  condition:
    any of them
}