rule TTP_XOR_QUAD_CurrentVersionRun_c39a {
  strings:
    $key_c39a = { 90 f5 [2] b4 fb [2] 9f d7 [2] b1 f5 [2] a5 ee [2] aa f4 [2] b4 e9 [2] b6 e8 [2] ad ee [2] b1 e9 [2] ad c6 }

  condition:
    any of them
}