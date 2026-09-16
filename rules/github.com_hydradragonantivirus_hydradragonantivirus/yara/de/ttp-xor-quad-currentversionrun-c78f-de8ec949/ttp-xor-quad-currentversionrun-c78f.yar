rule TTP_XOR_QUAD_CurrentVersionRun_c78f {
  strings:
    $key_c78f = { 94 e0 [2] b0 ee [2] 9b c2 [2] b5 e0 [2] a1 fb [2] ae e1 [2] b0 fc [2] b2 fd [2] a9 fb [2] b5 fc [2] a9 d3 }

  condition:
    any of them
}