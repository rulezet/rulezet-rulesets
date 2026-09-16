rule TTP_XOR_QUAD_CurrentVersionRun_d98f {
  strings:
    $key_d98f = { 8a e0 [2] ae ee [2] 85 c2 [2] ab e0 [2] bf fb [2] b0 e1 [2] ae fc [2] ac fd [2] b7 fb [2] ab fc [2] b7 d3 }

  condition:
    any of them
}