rule TTP_XOR_QUAD_CurrentVersionRun_c0a6 {
  strings:
    $key_c0a6 = { 93 c9 [2] b7 c7 [2] 9c eb [2] b2 c9 [2] a6 d2 [2] a9 c8 [2] b7 d5 [2] b5 d4 [2] ae d2 [2] b2 d5 [2] ae fa }

  condition:
    any of them
}