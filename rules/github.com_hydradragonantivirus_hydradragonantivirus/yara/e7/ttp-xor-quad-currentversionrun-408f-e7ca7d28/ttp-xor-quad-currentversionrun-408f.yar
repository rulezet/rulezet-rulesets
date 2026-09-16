rule TTP_XOR_QUAD_CurrentVersionRun_408f {
  strings:
    $key_408f = { 13 e0 [2] 37 ee [2] 1c c2 [2] 32 e0 [2] 26 fb [2] 29 e1 [2] 37 fc [2] 35 fd [2] 2e fb [2] 32 fc [2] 2e d3 }

  condition:
    any of them
}