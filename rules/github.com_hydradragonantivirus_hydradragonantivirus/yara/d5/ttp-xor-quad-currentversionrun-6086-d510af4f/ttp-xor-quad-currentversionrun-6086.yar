rule TTP_XOR_QUAD_CurrentVersionRun_6086 {
  strings:
    $key_6086 = { 33 e9 [2] 17 e7 [2] 3c cb [2] 12 e9 [2] 06 f2 [2] 09 e8 [2] 17 f5 [2] 15 f4 [2] 0e f2 [2] 12 f5 [2] 0e da }

  condition:
    any of them
}