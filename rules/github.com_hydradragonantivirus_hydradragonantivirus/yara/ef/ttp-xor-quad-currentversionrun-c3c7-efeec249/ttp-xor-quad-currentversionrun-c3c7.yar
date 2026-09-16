rule TTP_XOR_QUAD_CurrentVersionRun_c3c7 {
  strings:
    $key_c3c7 = { 90 a8 [2] b4 a6 [2] 9f 8a [2] b1 a8 [2] a5 b3 [2] aa a9 [2] b4 b4 [2] b6 b5 [2] ad b3 [2] b1 b4 [2] ad 9b }

  condition:
    any of them
}