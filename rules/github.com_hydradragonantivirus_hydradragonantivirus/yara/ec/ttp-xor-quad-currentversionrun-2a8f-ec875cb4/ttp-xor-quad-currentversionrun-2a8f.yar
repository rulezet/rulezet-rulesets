rule TTP_XOR_QUAD_CurrentVersionRun_2a8f {
  strings:
    $key_2a8f = { 79 e0 [2] 5d ee [2] 76 c2 [2] 58 e0 [2] 4c fb [2] 43 e1 [2] 5d fc [2] 5f fd [2] 44 fb [2] 58 fc [2] 44 d3 }

  condition:
    any of them
}