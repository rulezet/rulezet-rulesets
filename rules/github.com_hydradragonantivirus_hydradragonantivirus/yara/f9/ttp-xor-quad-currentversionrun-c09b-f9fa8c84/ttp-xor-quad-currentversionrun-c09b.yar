rule TTP_XOR_QUAD_CurrentVersionRun_c09b {
  strings:
    $key_c09b = { 93 f4 [2] b7 fa [2] 9c d6 [2] b2 f4 [2] a6 ef [2] a9 f5 [2] b7 e8 [2] b5 e9 [2] ae ef [2] b2 e8 [2] ae c7 }

  condition:
    any of them
}