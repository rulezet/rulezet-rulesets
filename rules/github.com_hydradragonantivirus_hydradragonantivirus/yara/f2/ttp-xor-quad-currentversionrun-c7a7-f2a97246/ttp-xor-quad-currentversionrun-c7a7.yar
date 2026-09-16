rule TTP_XOR_QUAD_CurrentVersionRun_c7a7 {
  strings:
    $key_c7a7 = { 94 c8 [2] b0 c6 [2] 9b ea [2] b5 c8 [2] a1 d3 [2] ae c9 [2] b0 d4 [2] b2 d5 [2] a9 d3 [2] b5 d4 [2] a9 fb }

  condition:
    any of them
}