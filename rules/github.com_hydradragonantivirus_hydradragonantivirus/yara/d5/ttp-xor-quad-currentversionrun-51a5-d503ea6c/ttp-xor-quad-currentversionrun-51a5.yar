rule TTP_XOR_QUAD_CurrentVersionRun_51a5 {
  strings:
    $key_51a5 = { 02 ca [2] 26 c4 [2] 0d e8 [2] 23 ca [2] 37 d1 [2] 38 cb [2] 26 d6 [2] 24 d7 [2] 3f d1 [2] 23 d6 [2] 3f f9 }

  condition:
    any of them
}