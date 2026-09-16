rule TTP_XOR_QUAD_CurrentVersionRun_148f {
  strings:
    $key_148f = { 47 e0 [2] 63 ee [2] 48 c2 [2] 66 e0 [2] 72 fb [2] 7d e1 [2] 63 fc [2] 61 fd [2] 7a fb [2] 66 fc [2] 7a d3 }

  condition:
    any of them
}