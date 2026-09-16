rule TTP_XOR_QUAD_CurrentVersionRun_13a5 {
  strings:
    $key_13a5 = { 40 ca [2] 64 c4 [2] 4f e8 [2] 61 ca [2] 75 d1 [2] 7a cb [2] 64 d6 [2] 66 d7 [2] 7d d1 [2] 61 d6 [2] 7d f9 }

  condition:
    any of them
}