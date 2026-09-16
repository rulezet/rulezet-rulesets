rule TTP_XOR_QUAD_CurrentVersionRun_2b8f {
  strings:
    $key_2b8f = { 78 e0 [2] 5c ee [2] 77 c2 [2] 59 e0 [2] 4d fb [2] 42 e1 [2] 5c fc [2] 5e fd [2] 45 fb [2] 59 fc [2] 45 d3 }

  condition:
    any of them
}