rule TTP_XOR_QUAD_CurrentVersionRun_ee8f {
  strings:
    $key_ee8f = { bd e0 [2] 99 ee [2] b2 c2 [2] 9c e0 [2] 88 fb [2] 87 e1 [2] 99 fc [2] 9b fd [2] 80 fb [2] 9c fc [2] 80 d3 }

  condition:
    any of them
}