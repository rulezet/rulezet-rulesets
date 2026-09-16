rule TTP_XOR_QUAD_CurrentVersionRun_77aa {
  strings:
    $key_77aa = { 24 c5 [2] 00 cb [2] 2b e7 [2] 05 c5 [2] 11 de [2] 1e c4 [2] 00 d9 [2] 02 d8 [2] 19 de [2] 05 d9 [2] 19 f6 }

  condition:
    any of them
}