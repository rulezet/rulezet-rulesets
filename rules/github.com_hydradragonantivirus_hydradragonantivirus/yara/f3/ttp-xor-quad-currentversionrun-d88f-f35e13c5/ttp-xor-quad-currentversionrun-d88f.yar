rule TTP_XOR_QUAD_CurrentVersionRun_d88f {
  strings:
    $key_d88f = { 8b e0 [2] af ee [2] 84 c2 [2] aa e0 [2] be fb [2] b1 e1 [2] af fc [2] ad fd [2] b6 fb [2] aa fc [2] b6 d3 }

  condition:
    any of them
}