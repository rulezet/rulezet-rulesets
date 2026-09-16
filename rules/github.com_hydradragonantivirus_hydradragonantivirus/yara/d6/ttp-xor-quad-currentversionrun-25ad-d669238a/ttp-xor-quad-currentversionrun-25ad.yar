rule TTP_XOR_QUAD_CurrentVersionRun_25ad {
  strings:
    $key_25ad = { 76 c2 [2] 52 cc [2] 79 e0 [2] 57 c2 [2] 43 d9 [2] 4c c3 [2] 52 de [2] 50 df [2] 4b d9 [2] 57 de [2] 4b f1 }

  condition:
    any of them
}