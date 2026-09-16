rule TTP_XOR_QUAD_CurrentVersionRun_ab86 {
  strings:
    $key_ab86 = { f8 e9 [2] dc e7 [2] f7 cb [2] d9 e9 [2] cd f2 [2] c2 e8 [2] dc f5 [2] de f4 [2] c5 f2 [2] d9 f5 [2] c5 da }

  condition:
    any of them
}