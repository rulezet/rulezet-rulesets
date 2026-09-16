rule TTP_XOR_QUAD_CurrentVersionRun_aec8 {
  strings:
    $key_aec8 = { fd a7 [2] d9 a9 [2] f2 85 [2] dc a7 [2] c8 bc [2] c7 a6 [2] d9 bb [2] db ba [2] c0 bc [2] dc bb [2] c0 94 }

  condition:
    any of them
}