rule TTP_XOR_QUAD_CurrentVersionRun_d19a {
  strings:
    $key_d19a = { 82 f5 [2] a6 fb [2] 8d d7 [2] a3 f5 [2] b7 ee [2] b8 f4 [2] a6 e9 [2] a4 e8 [2] bf ee [2] a3 e9 [2] bf c6 }

  condition:
    any of them
}