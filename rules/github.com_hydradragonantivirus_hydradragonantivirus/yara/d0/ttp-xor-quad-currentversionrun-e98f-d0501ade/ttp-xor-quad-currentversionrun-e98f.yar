rule TTP_XOR_QUAD_CurrentVersionRun_e98f {
  strings:
    $key_e98f = { ba e0 [2] 9e ee [2] b5 c2 [2] 9b e0 [2] 8f fb [2] 80 e1 [2] 9e fc [2] 9c fd [2] 87 fb [2] 9b fc [2] 87 d3 }

  condition:
    any of them
}