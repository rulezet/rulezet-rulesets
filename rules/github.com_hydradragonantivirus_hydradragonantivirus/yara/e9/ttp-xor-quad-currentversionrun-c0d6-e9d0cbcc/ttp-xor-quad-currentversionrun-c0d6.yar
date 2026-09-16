rule TTP_XOR_QUAD_CurrentVersionRun_c0d6 {
  strings:
    $key_c0d6 = { 93 b9 [2] b7 b7 [2] 9c 9b [2] b2 b9 [2] a6 a2 [2] a9 b8 [2] b7 a5 [2] b5 a4 [2] ae a2 [2] b2 a5 [2] ae 8a }

  condition:
    any of them
}