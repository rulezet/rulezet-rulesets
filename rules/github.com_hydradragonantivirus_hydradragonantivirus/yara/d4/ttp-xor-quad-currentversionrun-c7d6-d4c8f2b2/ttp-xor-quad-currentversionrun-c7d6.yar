rule TTP_XOR_QUAD_CurrentVersionRun_c7d6 {
  strings:
    $key_c7d6 = { 94 b9 [2] b0 b7 [2] 9b 9b [2] b5 b9 [2] a1 a2 [2] ae b8 [2] b0 a5 [2] b2 a4 [2] a9 a2 [2] b5 a5 [2] a9 8a }

  condition:
    any of them
}