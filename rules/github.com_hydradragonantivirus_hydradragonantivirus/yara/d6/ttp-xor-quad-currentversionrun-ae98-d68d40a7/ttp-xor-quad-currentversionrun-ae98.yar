rule TTP_XOR_QUAD_CurrentVersionRun_ae98 {
  strings:
    $key_ae98 = { fd f7 [2] d9 f9 [2] f2 d5 [2] dc f7 [2] c8 ec [2] c7 f6 [2] d9 eb [2] db ea [2] c0 ec [2] dc eb [2] c0 c4 }

  condition:
    any of them
}