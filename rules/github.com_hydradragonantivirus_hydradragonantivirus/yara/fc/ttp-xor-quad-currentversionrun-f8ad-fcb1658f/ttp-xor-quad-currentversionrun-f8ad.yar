rule TTP_XOR_QUAD_CurrentVersionRun_f8ad {
  strings:
    $key_f8ad = { ab c2 [2] 8f cc [2] a4 e0 [2] 8a c2 [2] 9e d9 [2] 91 c3 [2] 8f de [2] 8d df [2] 96 d9 [2] 8a de [2] 96 f1 }

  condition:
    any of them
}