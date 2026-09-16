rule TTP_XOR_QUAD_CurrentVersionRun_ec8f {
  strings:
    $key_ec8f = { bf e0 [2] 9b ee [2] b0 c2 [2] 9e e0 [2] 8a fb [2] 85 e1 [2] 9b fc [2] 99 fd [2] 82 fb [2] 9e fc [2] 82 d3 }

  condition:
    any of them
}