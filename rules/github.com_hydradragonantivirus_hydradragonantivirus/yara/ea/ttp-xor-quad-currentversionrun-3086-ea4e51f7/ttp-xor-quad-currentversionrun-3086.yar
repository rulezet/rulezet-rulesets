rule TTP_XOR_QUAD_CurrentVersionRun_3086 {
  strings:
    $key_3086 = { 63 e9 [2] 47 e7 [2] 6c cb [2] 42 e9 [2] 56 f2 [2] 59 e8 [2] 47 f5 [2] 45 f4 [2] 5e f2 [2] 42 f5 [2] 5e da }

  condition:
    any of them
}