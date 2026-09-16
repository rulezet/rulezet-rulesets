rule TTP_XOR_QUAD_CurrentVersionRun_07a5 {
  strings:
    $key_07a5 = { 54 ca [2] 70 c4 [2] 5b e8 [2] 75 ca [2] 61 d1 [2] 6e cb [2] 70 d6 [2] 72 d7 [2] 69 d1 [2] 75 d6 [2] 69 f9 }

  condition:
    any of them
}