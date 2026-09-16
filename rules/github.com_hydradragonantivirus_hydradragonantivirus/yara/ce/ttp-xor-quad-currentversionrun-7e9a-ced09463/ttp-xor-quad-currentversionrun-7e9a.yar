rule TTP_XOR_QUAD_CurrentVersionRun_7e9a {
  strings:
    $key_7e9a = { 2d f5 [2] 09 fb [2] 22 d7 [2] 0c f5 [2] 18 ee [2] 17 f4 [2] 09 e9 [2] 0b e8 [2] 10 ee [2] 0c e9 [2] 10 c6 }

  condition:
    any of them
}