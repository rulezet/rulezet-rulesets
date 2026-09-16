rule TTP_XOR_QUAD_CurrentVersionRun_a986 {
  strings:
    $key_a986 = { fa e9 [2] de e7 [2] f5 cb [2] db e9 [2] cf f2 [2] c0 e8 [2] de f5 [2] dc f4 [2] c7 f2 [2] db f5 [2] c7 da }

  condition:
    any of them
}