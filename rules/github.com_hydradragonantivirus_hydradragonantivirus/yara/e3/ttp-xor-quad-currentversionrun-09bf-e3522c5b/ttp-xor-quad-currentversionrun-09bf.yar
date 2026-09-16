rule TTP_XOR_QUAD_CurrentVersionRun_09bf {
  strings:
    $key_09bf = { 5a d0 [2] 7e de [2] 55 f2 [2] 7b d0 [2] 6f cb [2] 60 d1 [2] 7e cc [2] 7c cd [2] 67 cb [2] 7b cc [2] 67 e3 }

  condition:
    any of them
}