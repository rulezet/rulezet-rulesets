rule TTP_XOR_QUAD_CurrentVersionRun_fbac {
  strings:
    $key_fbac = { a8 c3 [2] 8c cd [2] a7 e1 [2] 89 c3 [2] 9d d8 [2] 92 c2 [2] 8c df [2] 8e de [2] 95 d8 [2] 89 df [2] 95 f0 }

  condition:
    any of them
}