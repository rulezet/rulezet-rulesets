rule TTP_XOR_QUAD_CurrentVersionRun_c0ba {
  strings:
    $key_c0ba = { 93 d5 [2] b7 db [2] 9c f7 [2] b2 d5 [2] a6 ce [2] a9 d4 [2] b7 c9 [2] b5 c8 [2] ae ce [2] b2 c9 [2] ae e6 }

  condition:
    any of them
}