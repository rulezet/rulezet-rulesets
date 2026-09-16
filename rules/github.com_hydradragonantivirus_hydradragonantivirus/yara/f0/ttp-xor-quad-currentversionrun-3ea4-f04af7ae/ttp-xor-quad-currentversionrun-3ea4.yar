rule TTP_XOR_QUAD_CurrentVersionRun_3ea4 {
  strings:
    $key_3ea4 = { 6d cb [2] 49 c5 [2] 62 e9 [2] 4c cb [2] 58 d0 [2] 57 ca [2] 49 d7 [2] 4b d6 [2] 50 d0 [2] 4c d7 [2] 50 f8 }

  condition:
    any of them
}