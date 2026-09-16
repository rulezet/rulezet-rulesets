rule TTP_XOR_QUAD_CurrentVersionRun_6caa {
  strings:
    $key_6caa = { 3f c5 [2] 1b cb [2] 30 e7 [2] 1e c5 [2] 0a de [2] 05 c4 [2] 1b d9 [2] 19 d8 [2] 02 de [2] 1e d9 [2] 02 f6 }

  condition:
    any of them
}