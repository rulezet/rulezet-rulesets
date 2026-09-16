rule TTP_XOR_QUAD_CurrentVersionRun_6eaa {
  strings:
    $key_6eaa = { 3d c5 [2] 19 cb [2] 32 e7 [2] 1c c5 [2] 08 de [2] 07 c4 [2] 19 d9 [2] 1b d8 [2] 00 de [2] 1c d9 [2] 00 f6 }

  condition:
    any of them
}