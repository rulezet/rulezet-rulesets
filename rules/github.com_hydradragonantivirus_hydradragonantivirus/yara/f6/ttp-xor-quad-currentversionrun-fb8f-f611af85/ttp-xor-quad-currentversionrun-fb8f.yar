rule TTP_XOR_QUAD_CurrentVersionRun_fb8f {
  strings:
    $key_fb8f = { a8 e0 [2] 8c ee [2] a7 c2 [2] 89 e0 [2] 9d fb [2] 92 e1 [2] 8c fc [2] 8e fd [2] 95 fb [2] 89 fc [2] 95 d3 }

  condition:
    any of them
}