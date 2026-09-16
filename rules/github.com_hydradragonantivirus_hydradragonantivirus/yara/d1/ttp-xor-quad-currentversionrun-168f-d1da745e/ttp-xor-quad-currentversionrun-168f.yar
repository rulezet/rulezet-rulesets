rule TTP_XOR_QUAD_CurrentVersionRun_168f {
  strings:
    $key_168f = { 45 e0 [2] 61 ee [2] 4a c2 [2] 64 e0 [2] 70 fb [2] 7f e1 [2] 61 fc [2] 63 fd [2] 78 fb [2] 64 fc [2] 78 d3 }

  condition:
    any of them
}