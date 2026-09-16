rule TTP_XOR_QUAD_CurrentVersionRun_1fad {
  strings:
    $key_1fad = { 4c c2 [2] 68 cc [2] 43 e0 [2] 6d c2 [2] 79 d9 [2] 76 c3 [2] 68 de [2] 6a df [2] 71 d9 [2] 6d de [2] 71 f1 }

  condition:
    any of them
}