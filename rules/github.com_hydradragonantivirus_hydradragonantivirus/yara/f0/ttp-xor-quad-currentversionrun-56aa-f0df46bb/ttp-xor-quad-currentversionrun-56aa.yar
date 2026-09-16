rule TTP_XOR_QUAD_CurrentVersionRun_56aa {
  strings:
    $key_56aa = { 05 c5 [2] 21 cb [2] 0a e7 [2] 24 c5 [2] 30 de [2] 3f c4 [2] 21 d9 [2] 23 d8 [2] 38 de [2] 24 d9 [2] 38 f6 }

  condition:
    any of them
}