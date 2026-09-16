rule TTP_XOR_QUAD_CurrentVersionRun_68ad {
  strings:
    $key_68ad = { 3b c2 [2] 1f cc [2] 34 e0 [2] 1a c2 [2] 0e d9 [2] 01 c3 [2] 1f de [2] 1d df [2] 06 d9 [2] 1a de [2] 06 f1 }

  condition:
    any of them
}