rule TTP_XOR_QUAD_CurrentVersionRun_07aa {
  strings:
    $key_07aa = { 54 c5 [2] 70 cb [2] 5b e7 [2] 75 c5 [2] 61 de [2] 6e c4 [2] 70 d9 [2] 72 d8 [2] 69 de [2] 75 d9 [2] 69 f6 }

  condition:
    any of them
}