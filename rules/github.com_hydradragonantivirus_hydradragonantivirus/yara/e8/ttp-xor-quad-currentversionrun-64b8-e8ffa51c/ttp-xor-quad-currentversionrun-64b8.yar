rule TTP_XOR_QUAD_CurrentVersionRun_64b8 {
  strings:
    $key_64b8 = { 37 d7 [2] 13 d9 [2] 38 f5 [2] 16 d7 [2] 02 cc [2] 0d d6 [2] 13 cb [2] 11 ca [2] 0a cc [2] 16 cb [2] 0a e4 }

  condition:
    any of them
}