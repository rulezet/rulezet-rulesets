rule TTP_XOR_QUAD_CurrentVersionRun_3caa {
  strings:
    $key_3caa = { 6f c5 [2] 4b cb [2] 60 e7 [2] 4e c5 [2] 5a de [2] 55 c4 [2] 4b d9 [2] 49 d8 [2] 52 de [2] 4e d9 [2] 52 f6 }

  condition:
    any of them
}