rule TTP_XOR_QUAD_CurrentVersionRun_e2aa {
  strings:
    $key_e2aa = { b1 c5 [2] 95 cb [2] be e7 [2] 90 c5 [2] 84 de [2] 8b c4 [2] 95 d9 [2] 97 d8 [2] 8c de [2] 90 d9 [2] 8c f6 }

  condition:
    any of them
}