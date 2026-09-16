rule TTP_XOR_QUAD_CurrentVersionRun_fea4 {
  strings:
    $key_fea4 = { ad cb [2] 89 c5 [2] a2 e9 [2] 8c cb [2] 98 d0 [2] 97 ca [2] 89 d7 [2] 8b d6 [2] 90 d0 [2] 8c d7 [2] 90 f8 }

  condition:
    any of them
}