rule TTP_XOR_QUAD_CurrentVersionRun_4dad {
  strings:
    $key_4dad = { 1e c2 [2] 3a cc [2] 11 e0 [2] 3f c2 [2] 2b d9 [2] 24 c3 [2] 3a de [2] 38 df [2] 23 d9 [2] 3f de [2] 23 f1 }

  condition:
    any of them
}