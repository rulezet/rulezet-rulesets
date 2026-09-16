rule TTP_XOR_QUAD_CurrentVersionRun_ae8f {
  strings:
    $key_ae8f = { fd e0 [2] d9 ee [2] f2 c2 [2] dc e0 [2] c8 fb [2] c7 e1 [2] d9 fc [2] db fd [2] c0 fb [2] dc fc [2] c0 d3 }

  condition:
    any of them
}