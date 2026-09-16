rule TTP_XOR_QUAD_CurrentVersionRun_c0b4 {
  strings:
    $key_c0b4 = { 93 db [2] b7 d5 [2] 9c f9 [2] b2 db [2] a6 c0 [2] a9 da [2] b7 c7 [2] b5 c6 [2] ae c0 [2] b2 c7 [2] ae e8 }

  condition:
    any of them
}