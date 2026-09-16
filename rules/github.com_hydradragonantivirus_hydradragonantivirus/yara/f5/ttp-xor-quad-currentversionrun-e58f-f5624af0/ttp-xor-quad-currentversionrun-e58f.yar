rule TTP_XOR_QUAD_CurrentVersionRun_e58f {
  strings:
    $key_e58f = { b6 e0 [2] 92 ee [2] b9 c2 [2] 97 e0 [2] 83 fb [2] 8c e1 [2] 92 fc [2] 90 fd [2] 8b fb [2] 97 fc [2] 8b d3 }

  condition:
    any of them
}