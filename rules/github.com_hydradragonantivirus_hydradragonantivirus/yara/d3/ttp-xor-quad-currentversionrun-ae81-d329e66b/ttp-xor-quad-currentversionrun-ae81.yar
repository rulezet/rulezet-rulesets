rule TTP_XOR_QUAD_CurrentVersionRun_ae81 {
  strings:
    $key_ae81 = { fd ee [2] d9 e0 [2] f2 cc [2] dc ee [2] c8 f5 [2] c7 ef [2] d9 f2 [2] db f3 [2] c0 f5 [2] dc f2 [2] c0 dd }

  condition:
    any of them
}