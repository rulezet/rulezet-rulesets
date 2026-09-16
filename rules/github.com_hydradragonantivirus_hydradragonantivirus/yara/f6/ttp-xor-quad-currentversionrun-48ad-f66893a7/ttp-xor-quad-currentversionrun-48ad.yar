rule TTP_XOR_QUAD_CurrentVersionRun_48ad {
  strings:
    $key_48ad = { 1b c2 [2] 3f cc [2] 14 e0 [2] 3a c2 [2] 2e d9 [2] 21 c3 [2] 3f de [2] 3d df [2] 26 d9 [2] 3a de [2] 26 f1 }

  condition:
    any of them
}