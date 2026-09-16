rule TTP_XOR_QUAD_CurrentVersionRun_dd96 {
  strings:
    $key_dd96 = { 8e f9 [2] aa f7 [2] 81 db [2] af f9 [2] bb e2 [2] b4 f8 [2] aa e5 [2] a8 e4 [2] b3 e2 [2] af e5 [2] b3 ca }

  condition:
    any of them
}