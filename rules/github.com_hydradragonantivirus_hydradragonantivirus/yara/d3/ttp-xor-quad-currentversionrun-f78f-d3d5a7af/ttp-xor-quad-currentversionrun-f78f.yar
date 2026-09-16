rule TTP_XOR_QUAD_CurrentVersionRun_f78f {
  strings:
    $key_f78f = { a4 e0 [2] 80 ee [2] ab c2 [2] 85 e0 [2] 91 fb [2] 9e e1 [2] 80 fc [2] 82 fd [2] 99 fb [2] 85 fc [2] 99 d3 }

  condition:
    any of them
}