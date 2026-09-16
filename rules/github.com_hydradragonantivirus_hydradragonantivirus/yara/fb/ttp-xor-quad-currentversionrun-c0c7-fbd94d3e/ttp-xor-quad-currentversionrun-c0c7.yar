rule TTP_XOR_QUAD_CurrentVersionRun_c0c7 {
  strings:
    $key_c0c7 = { 93 a8 [2] b7 a6 [2] 9c 8a [2] b2 a8 [2] a6 b3 [2] a9 a9 [2] b7 b4 [2] b5 b5 [2] ae b3 [2] b2 b4 [2] ae 9b }

  condition:
    any of them
}