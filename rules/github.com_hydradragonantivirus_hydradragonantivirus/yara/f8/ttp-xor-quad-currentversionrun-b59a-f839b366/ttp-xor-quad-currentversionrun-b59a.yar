rule TTP_XOR_QUAD_CurrentVersionRun_b59a {
  strings:
    $key_b59a = { e6 f5 [2] c2 fb [2] e9 d7 [2] c7 f5 [2] d3 ee [2] dc f4 [2] c2 e9 [2] c0 e8 [2] db ee [2] c7 e9 [2] db c6 }

  condition:
    any of them
}