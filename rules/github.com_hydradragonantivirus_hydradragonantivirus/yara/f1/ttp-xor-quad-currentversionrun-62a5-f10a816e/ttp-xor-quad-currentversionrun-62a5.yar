rule TTP_XOR_QUAD_CurrentVersionRun_62a5 {
  strings:
    $key_62a5 = { 31 ca [2] 15 c4 [2] 3e e8 [2] 10 ca [2] 04 d1 [2] 0b cb [2] 15 d6 [2] 17 d7 [2] 0c d1 [2] 10 d6 [2] 0c f9 }

  condition:
    any of them
}