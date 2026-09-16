rule TTP_XOR_QUAD_CurrentVersionRun_6daa {
  strings:
    $key_6daa = { 3e c5 [2] 1a cb [2] 31 e7 [2] 1f c5 [2] 0b de [2] 04 c4 [2] 1a d9 [2] 18 d8 [2] 03 de [2] 1f d9 [2] 03 f6 }

  condition:
    any of them
}