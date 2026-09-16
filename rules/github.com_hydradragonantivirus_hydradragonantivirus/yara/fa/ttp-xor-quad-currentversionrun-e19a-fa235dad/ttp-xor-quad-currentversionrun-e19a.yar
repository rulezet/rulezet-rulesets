rule TTP_XOR_QUAD_CurrentVersionRun_e19a {
  strings:
    $key_e19a = { b2 f5 [2] 96 fb [2] bd d7 [2] 93 f5 [2] 87 ee [2] 88 f4 [2] 96 e9 [2] 94 e8 [2] 8f ee [2] 93 e9 [2] 8f c6 }

  condition:
    any of them
}