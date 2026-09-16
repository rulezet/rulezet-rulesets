rule TTP_XOR_QUAD_CurrentVersionRun_ae9d {
  strings:
    $key_ae9d = { fd f2 [2] d9 fc [2] f2 d0 [2] dc f2 [2] c8 e9 [2] c7 f3 [2] d9 ee [2] db ef [2] c0 e9 [2] dc ee [2] c0 c1 }

  condition:
    any of them
}