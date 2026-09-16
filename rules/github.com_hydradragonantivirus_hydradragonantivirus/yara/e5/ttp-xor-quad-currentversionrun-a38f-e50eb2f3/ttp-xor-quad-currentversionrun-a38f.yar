rule TTP_XOR_QUAD_CurrentVersionRun_a38f {
  strings:
    $key_a38f = { f0 e0 [2] d4 ee [2] ff c2 [2] d1 e0 [2] c5 fb [2] ca e1 [2] d4 fc [2] d6 fd [2] cd fb [2] d1 fc [2] cd d3 }

  condition:
    any of them
}