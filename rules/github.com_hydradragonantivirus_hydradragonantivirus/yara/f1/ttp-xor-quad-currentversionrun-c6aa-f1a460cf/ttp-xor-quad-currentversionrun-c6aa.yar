rule TTP_XOR_QUAD_CurrentVersionRun_c6aa {
  strings:
    $key_c6aa = { 95 c5 [2] b1 cb [2] 9a e7 [2] b4 c5 [2] a0 de [2] af c4 [2] b1 d9 [2] b3 d8 [2] a8 de [2] b4 d9 [2] a8 f6 }

  condition:
    any of them
}