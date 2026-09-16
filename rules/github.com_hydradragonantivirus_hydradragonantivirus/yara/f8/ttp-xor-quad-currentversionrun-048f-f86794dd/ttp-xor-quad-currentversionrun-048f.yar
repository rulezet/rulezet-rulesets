rule TTP_XOR_QUAD_CurrentVersionRun_048f {
  strings:
    $key_048f = { 57 e0 [2] 73 ee [2] 58 c2 [2] 76 e0 [2] 62 fb [2] 6d e1 [2] 73 fc [2] 71 fd [2] 6a fb [2] 76 fc [2] 6a d3 }

  condition:
    any of them
}