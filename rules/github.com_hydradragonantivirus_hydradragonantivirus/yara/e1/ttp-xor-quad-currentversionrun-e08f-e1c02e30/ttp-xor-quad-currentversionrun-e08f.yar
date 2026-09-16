rule TTP_XOR_QUAD_CurrentVersionRun_e08f {
  strings:
    $key_e08f = { b3 e0 [2] 97 ee [2] bc c2 [2] 92 e0 [2] 86 fb [2] 89 e1 [2] 97 fc [2] 95 fd [2] 8e fb [2] 92 fc [2] 8e d3 }

  condition:
    any of them
}