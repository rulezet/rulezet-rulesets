rule TTP_XOR_QUAD_CurrentVersionRun_46aa {
  strings:
    $key_46aa = { 15 c5 [2] 31 cb [2] 1a e7 [2] 34 c5 [2] 20 de [2] 2f c4 [2] 31 d9 [2] 33 d8 [2] 28 de [2] 34 d9 [2] 28 f6 }

  condition:
    any of them
}