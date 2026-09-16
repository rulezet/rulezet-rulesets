rule TTP_XOR_QUAD_CurrentVersionRun_ae84 {
  strings:
    $key_ae84 = { fd eb [2] d9 e5 [2] f2 c9 [2] dc eb [2] c8 f0 [2] c7 ea [2] d9 f7 [2] db f6 [2] c0 f0 [2] dc f7 [2] c0 d8 }

  condition:
    any of them
}