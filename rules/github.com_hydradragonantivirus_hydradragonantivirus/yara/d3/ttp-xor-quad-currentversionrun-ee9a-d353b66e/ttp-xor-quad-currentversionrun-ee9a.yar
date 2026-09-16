rule TTP_XOR_QUAD_CurrentVersionRun_ee9a {
  strings:
    $key_ee9a = { bd f5 [2] 99 fb [2] b2 d7 [2] 9c f5 [2] 88 ee [2] 87 f4 [2] 99 e9 [2] 9b e8 [2] 80 ee [2] 9c e9 [2] 80 c6 }

  condition:
    any of them
}