rule TTP_XOR_QUAD_CurrentVersionRun_b29a {
  strings:
    $key_b29a = { e1 f5 [2] c5 fb [2] ee d7 [2] c0 f5 [2] d4 ee [2] db f4 [2] c5 e9 [2] c7 e8 [2] dc ee [2] c0 e9 [2] dc c6 }

  condition:
    any of them
}