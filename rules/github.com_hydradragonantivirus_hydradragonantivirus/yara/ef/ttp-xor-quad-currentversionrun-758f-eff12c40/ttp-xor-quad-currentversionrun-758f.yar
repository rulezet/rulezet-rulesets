rule TTP_XOR_QUAD_CurrentVersionRun_758f {
  strings:
    $key_758f = { 26 e0 [2] 02 ee [2] 29 c2 [2] 07 e0 [2] 13 fb [2] 1c e1 [2] 02 fc [2] 00 fd [2] 1b fb [2] 07 fc [2] 1b d3 }

  condition:
    any of them
}