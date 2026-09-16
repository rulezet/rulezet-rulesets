rule TTP_XOR_QUAD_CurrentVersionRun_0bad {
  strings:
    $key_0bad = { 58 c2 [2] 7c cc [2] 57 e0 [2] 79 c2 [2] 6d d9 [2] 62 c3 [2] 7c de [2] 7e df [2] 65 d9 [2] 79 de [2] 65 f1 }

  condition:
    any of them
}