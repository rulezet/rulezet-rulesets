rule TTP_XOR_QUAD_CurrentVersionRun_e48f {
  strings:
    $key_e48f = { b7 e0 [2] 93 ee [2] b8 c2 [2] 96 e0 [2] 82 fb [2] 8d e1 [2] 93 fc [2] 91 fd [2] 8a fb [2] 96 fc [2] 8a d3 }

  condition:
    any of them
}