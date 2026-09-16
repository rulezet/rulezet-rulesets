rule TTP_XOR_QUAD_CurrentVersionRun_32a5 {
  strings:
    $key_32a5 = { 61 ca [2] 45 c4 [2] 6e e8 [2] 40 ca [2] 54 d1 [2] 5b cb [2] 45 d6 [2] 47 d7 [2] 5c d1 [2] 40 d6 [2] 5c f9 }

  condition:
    any of them
}