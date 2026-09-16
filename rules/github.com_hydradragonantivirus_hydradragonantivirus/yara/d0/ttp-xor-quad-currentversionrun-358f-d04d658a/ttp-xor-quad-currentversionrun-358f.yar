rule TTP_XOR_QUAD_CurrentVersionRun_358f {
  strings:
    $key_358f = { 66 e0 [2] 42 ee [2] 69 c2 [2] 47 e0 [2] 53 fb [2] 5c e1 [2] 42 fc [2] 40 fd [2] 5b fb [2] 47 fc [2] 5b d3 }

  condition:
    any of them
}