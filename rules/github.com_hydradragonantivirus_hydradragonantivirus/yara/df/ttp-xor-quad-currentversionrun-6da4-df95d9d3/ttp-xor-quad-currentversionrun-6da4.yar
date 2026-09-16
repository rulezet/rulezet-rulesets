rule TTP_XOR_QUAD_CurrentVersionRun_6da4 {
  strings:
    $key_6da4 = { 3e cb [2] 1a c5 [2] 31 e9 [2] 1f cb [2] 0b d0 [2] 04 ca [2] 1a d7 [2] 18 d6 [2] 03 d0 [2] 1f d7 [2] 03 f8 }

  condition:
    any of them
}