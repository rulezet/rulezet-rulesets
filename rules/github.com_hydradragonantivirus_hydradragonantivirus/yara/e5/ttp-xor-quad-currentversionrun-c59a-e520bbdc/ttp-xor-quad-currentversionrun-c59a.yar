rule TTP_XOR_QUAD_CurrentVersionRun_c59a {
  strings:
    $key_c59a = { 96 f5 [2] b2 fb [2] 99 d7 [2] b7 f5 [2] a3 ee [2] ac f4 [2] b2 e9 [2] b0 e8 [2] ab ee [2] b7 e9 [2] ab c6 }

  condition:
    any of them
}