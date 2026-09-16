rule TTP_XOR_QUAD_CurrentVersionRun_ab8f {
  strings:
    $key_ab8f = { f8 e0 [2] dc ee [2] f7 c2 [2] d9 e0 [2] cd fb [2] c2 e1 [2] dc fc [2] de fd [2] c5 fb [2] d9 fc [2] c5 d3 }

  condition:
    any of them
}