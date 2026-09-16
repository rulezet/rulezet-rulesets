rule TTP_XOR_QUAD_CurrentVersionRun_bbaa {
  strings:
    $key_bbaa = { e8 c5 [2] cc cb [2] e7 e7 [2] c9 c5 [2] dd de [2] d2 c4 [2] cc d9 [2] ce d8 [2] d5 de [2] c9 d9 [2] d5 f6 }

  condition:
    any of them
}