rule TTP_XOR_QUAD_CurrentVersionRun_75b8 {
  strings:
    $key_75b8 = { 26 d7 [2] 02 d9 [2] 29 f5 [2] 07 d7 [2] 13 cc [2] 1c d6 [2] 02 cb [2] 00 ca [2] 1b cc [2] 07 cb [2] 1b e4 }

  condition:
    any of them
}