rule TTP_XOR_QUAD_CurrentVersionRun_19bf {
  strings:
    $key_19bf = { 4a d0 [2] 6e de [2] 45 f2 [2] 6b d0 [2] 7f cb [2] 70 d1 [2] 6e cc [2] 6c cd [2] 77 cb [2] 6b cc [2] 77 e3 }

  condition:
    any of them
}