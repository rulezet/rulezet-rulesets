rule TTP_XOR_QUAD_CurrentVersionRun_c6a6 {
  strings:
    $key_c6a6 = { 95 c9 [2] b1 c7 [2] 9a eb [2] b4 c9 [2] a0 d2 [2] af c8 [2] b1 d5 [2] b3 d4 [2] a8 d2 [2] b4 d5 [2] a8 fa }

  condition:
    any of them
}