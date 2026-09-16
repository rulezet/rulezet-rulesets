rule TTP_XOR_QUAD_CurrentVersionRun_2ea4 {
  strings:
    $key_2ea4 = { 7d cb [2] 59 c5 [2] 72 e9 [2] 5c cb [2] 48 d0 [2] 47 ca [2] 59 d7 [2] 5b d6 [2] 40 d0 [2] 5c d7 [2] 40 f8 }

  condition:
    any of them
}