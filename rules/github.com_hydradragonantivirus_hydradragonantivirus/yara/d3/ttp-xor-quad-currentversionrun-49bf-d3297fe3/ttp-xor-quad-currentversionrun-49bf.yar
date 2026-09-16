rule TTP_XOR_QUAD_CurrentVersionRun_49bf {
  strings:
    $key_49bf = { 1a d0 [2] 3e de [2] 15 f2 [2] 3b d0 [2] 2f cb [2] 20 d1 [2] 3e cc [2] 3c cd [2] 27 cb [2] 3b cc [2] 27 e3 }

  condition:
    any of them
}