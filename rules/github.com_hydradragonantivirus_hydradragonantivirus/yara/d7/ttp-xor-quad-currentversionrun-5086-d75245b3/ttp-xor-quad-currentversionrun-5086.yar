rule TTP_XOR_QUAD_CurrentVersionRun_5086 {
  strings:
    $key_5086 = { 03 e9 [2] 27 e7 [2] 0c cb [2] 22 e9 [2] 36 f2 [2] 39 e8 [2] 27 f5 [2] 25 f4 [2] 3e f2 [2] 22 f5 [2] 3e da }

  condition:
    any of them
}