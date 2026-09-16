rule TTP_XOR_QUAD_CurrentVersionRun_15b8 {
  strings:
    $key_15b8 = { 46 d7 [2] 62 d9 [2] 49 f5 [2] 67 d7 [2] 73 cc [2] 7c d6 [2] 62 cb [2] 60 ca [2] 7b cc [2] 67 cb [2] 7b e4 }

  condition:
    any of them
}