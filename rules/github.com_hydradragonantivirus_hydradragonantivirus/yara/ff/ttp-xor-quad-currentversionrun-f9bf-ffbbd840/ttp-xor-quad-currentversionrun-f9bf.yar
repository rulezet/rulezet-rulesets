rule TTP_XOR_QUAD_CurrentVersionRun_f9bf {
  strings:
    $key_f9bf = { aa d0 [2] 8e de [2] a5 f2 [2] 8b d0 [2] 9f cb [2] 90 d1 [2] 8e cc [2] 8c cd [2] 97 cb [2] 8b cc [2] 97 e3 }

  condition:
    any of them
}