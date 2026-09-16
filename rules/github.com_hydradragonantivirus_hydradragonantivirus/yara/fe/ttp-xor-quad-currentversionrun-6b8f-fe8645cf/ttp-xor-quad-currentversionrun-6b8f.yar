rule TTP_XOR_QUAD_CurrentVersionRun_6b8f {
  strings:
    $key_6b8f = { 38 e0 [2] 1c ee [2] 37 c2 [2] 19 e0 [2] 0d fb [2] 02 e1 [2] 1c fc [2] 1e fd [2] 05 fb [2] 19 fc [2] 05 d3 }

  condition:
    any of them
}