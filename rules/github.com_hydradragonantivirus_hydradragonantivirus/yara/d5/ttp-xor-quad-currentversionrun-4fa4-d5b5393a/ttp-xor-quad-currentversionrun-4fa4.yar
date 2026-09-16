rule TTP_XOR_QUAD_CurrentVersionRun_4fa4 {
  strings:
    $key_4fa4 = { 1c cb [2] 38 c5 [2] 13 e9 [2] 3d cb [2] 29 d0 [2] 26 ca [2] 38 d7 [2] 3a d6 [2] 21 d0 [2] 3d d7 [2] 21 f8 }

  condition:
    any of them
}