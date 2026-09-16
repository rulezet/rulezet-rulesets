rule TTP_XOR_QUAD_CurrentVersionRun_c3ca {
  strings:
    $key_c3ca = { 90 a5 [2] b4 ab [2] 9f 87 [2] b1 a5 [2] a5 be [2] aa a4 [2] b4 b9 [2] b6 b8 [2] ad be [2] b1 b9 [2] ad 96 }

  condition:
    any of them
}