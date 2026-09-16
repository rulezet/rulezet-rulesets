rule TTP_XOR_QUAD_CurrentVersionRun_51a4 {
  strings:
    $key_51a4 = { 02 cb [2] 26 c5 [2] 0d e9 [2] 23 cb [2] 37 d0 [2] 38 ca [2] 26 d7 [2] 24 d6 [2] 3f d0 [2] 23 d7 [2] 3f f8 }

  condition:
    any of them
}