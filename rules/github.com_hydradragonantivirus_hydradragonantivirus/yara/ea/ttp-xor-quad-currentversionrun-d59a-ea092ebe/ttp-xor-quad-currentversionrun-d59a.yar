rule TTP_XOR_QUAD_CurrentVersionRun_d59a {
  strings:
    $key_d59a = { 86 f5 [2] a2 fb [2] 89 d7 [2] a7 f5 [2] b3 ee [2] bc f4 [2] a2 e9 [2] a0 e8 [2] bb ee [2] a7 e9 [2] bb c6 }

  condition:
    any of them
}