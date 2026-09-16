rule TTP_XOR_QUAD_CurrentVersionRun_57a5 {
  strings:
    $key_57a5 = { 04 ca [2] 20 c4 [2] 0b e8 [2] 25 ca [2] 31 d1 [2] 3e cb [2] 20 d6 [2] 22 d7 [2] 39 d1 [2] 25 d6 [2] 39 f9 }

  condition:
    any of them
}