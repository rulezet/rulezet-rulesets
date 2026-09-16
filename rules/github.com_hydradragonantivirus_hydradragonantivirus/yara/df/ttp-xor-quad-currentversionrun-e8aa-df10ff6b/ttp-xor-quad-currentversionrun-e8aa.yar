rule TTP_XOR_QUAD_CurrentVersionRun_e8aa {
  strings:
    $key_e8aa = { bb c5 [2] 9f cb [2] b4 e7 [2] 9a c5 [2] 8e de [2] 81 c4 [2] 9f d9 [2] 9d d8 [2] 86 de [2] 9a d9 [2] 86 f6 }

  condition:
    any of them
}