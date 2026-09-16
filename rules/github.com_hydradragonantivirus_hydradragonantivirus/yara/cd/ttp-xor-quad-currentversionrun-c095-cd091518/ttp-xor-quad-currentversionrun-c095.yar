rule TTP_XOR_QUAD_CurrentVersionRun_c095 {
  strings:
    $key_c095 = { 93 fa [2] b7 f4 [2] 9c d8 [2] b2 fa [2] a6 e1 [2] a9 fb [2] b7 e6 [2] b5 e7 [2] ae e1 [2] b2 e6 [2] ae c9 }

  condition:
    any of them
}