rule TTP_XOR_QUAD_CurrentVersionRun_45b8 {
  strings:
    $key_45b8 = { 16 d7 [2] 32 d9 [2] 19 f5 [2] 37 d7 [2] 23 cc [2] 2c d6 [2] 32 cb [2] 30 ca [2] 2b cc [2] 37 cb [2] 2b e4 }

  condition:
    any of them
}