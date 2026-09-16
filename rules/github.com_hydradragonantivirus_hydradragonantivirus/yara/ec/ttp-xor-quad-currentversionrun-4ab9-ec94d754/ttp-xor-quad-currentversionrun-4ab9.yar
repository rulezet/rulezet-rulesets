rule TTP_XOR_QUAD_CurrentVersionRun_4ab9 {
  strings:
    $key_4ab9 = { 19 d6 [2] 3d d8 [2] 16 f4 [2] 38 d6 [2] 2c cd [2] 23 d7 [2] 3d ca [2] 3f cb [2] 24 cd [2] 38 ca [2] 24 e5 }

  condition:
    any of them
}