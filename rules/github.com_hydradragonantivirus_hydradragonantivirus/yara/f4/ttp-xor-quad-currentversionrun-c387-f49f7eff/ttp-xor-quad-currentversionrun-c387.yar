rule TTP_XOR_QUAD_CurrentVersionRun_c387 {
  strings:
    $key_c387 = { 90 e8 [2] b4 e6 [2] 9f ca [2] b1 e8 [2] a5 f3 [2] aa e9 [2] b4 f4 [2] b6 f5 [2] ad f3 [2] b1 f4 [2] ad db }

  condition:
    any of them
}