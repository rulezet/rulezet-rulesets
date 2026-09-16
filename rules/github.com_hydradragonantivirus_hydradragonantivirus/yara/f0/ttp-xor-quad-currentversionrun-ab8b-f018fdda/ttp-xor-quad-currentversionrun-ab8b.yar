rule TTP_XOR_QUAD_CurrentVersionRun_ab8b {
  strings:
    $key_ab8b = { f8 e4 [2] dc ea [2] f7 c6 [2] d9 e4 [2] cd ff [2] c2 e5 [2] dc f8 [2] de f9 [2] c5 ff [2] d9 f8 [2] c5 d7 }

  condition:
    any of them
}