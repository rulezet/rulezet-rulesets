rule TTP_XOR_QUAD_CurrentVersionRun_e8ad {
  strings:
    $key_e8ad = { bb c2 [2] 9f cc [2] b4 e0 [2] 9a c2 [2] 8e d9 [2] 81 c3 [2] 9f de [2] 9d df [2] 86 d9 [2] 9a de [2] 86 f1 }

  condition:
    any of them
}