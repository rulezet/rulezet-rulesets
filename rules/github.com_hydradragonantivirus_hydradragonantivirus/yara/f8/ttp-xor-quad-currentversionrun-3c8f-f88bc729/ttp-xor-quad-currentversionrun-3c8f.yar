rule TTP_XOR_QUAD_CurrentVersionRun_3c8f {
  strings:
    $key_3c8f = { 6f e0 [2] 4b ee [2] 60 c2 [2] 4e e0 [2] 5a fb [2] 55 e1 [2] 4b fc [2] 49 fd [2] 52 fb [2] 4e fc [2] 52 d3 }

  condition:
    any of them
}