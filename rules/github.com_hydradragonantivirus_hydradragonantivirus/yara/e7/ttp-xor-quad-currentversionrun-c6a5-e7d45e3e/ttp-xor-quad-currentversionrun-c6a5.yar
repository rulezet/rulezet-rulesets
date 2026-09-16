rule TTP_XOR_QUAD_CurrentVersionRun_c6a5 {
  strings:
    $key_c6a5 = { 95 ca [2] b1 c4 [2] 9a e8 [2] b4 ca [2] a0 d1 [2] af cb [2] b1 d6 [2] b3 d7 [2] a8 d1 [2] b4 d6 [2] a8 f9 }

  condition:
    any of them
}