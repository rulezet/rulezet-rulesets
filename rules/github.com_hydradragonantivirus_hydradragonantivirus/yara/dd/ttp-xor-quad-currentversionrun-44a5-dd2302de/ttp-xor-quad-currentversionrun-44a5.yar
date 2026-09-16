rule TTP_XOR_QUAD_CurrentVersionRun_44a5 {
  strings:
    $key_44a5 = { 17 ca [2] 33 c4 [2] 18 e8 [2] 36 ca [2] 22 d1 [2] 2d cb [2] 33 d6 [2] 31 d7 [2] 2a d1 [2] 36 d6 [2] 2a f9 }

  condition:
    any of them
}