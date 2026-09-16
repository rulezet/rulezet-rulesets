rule TTP_XOR_QUAD_CurrentVersionRun_c1a6 {
  strings:
    $key_c1a6 = { 92 c9 [2] b6 c7 [2] 9d eb [2] b3 c9 [2] a7 d2 [2] a8 c8 [2] b6 d5 [2] b4 d4 [2] af d2 [2] b3 d5 [2] af fa }

  condition:
    any of them
}