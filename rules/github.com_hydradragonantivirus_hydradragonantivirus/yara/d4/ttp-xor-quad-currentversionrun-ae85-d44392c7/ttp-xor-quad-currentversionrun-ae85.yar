rule TTP_XOR_QUAD_CurrentVersionRun_ae85 {
  strings:
    $key_ae85 = { fd ea [2] d9 e4 [2] f2 c8 [2] dc ea [2] c8 f1 [2] c7 eb [2] d9 f6 [2] db f7 [2] c0 f1 [2] dc f6 [2] c0 d9 }

  condition:
    any of them
}