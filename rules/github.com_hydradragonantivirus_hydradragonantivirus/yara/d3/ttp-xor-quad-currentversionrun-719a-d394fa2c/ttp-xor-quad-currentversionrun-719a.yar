rule TTP_XOR_QUAD_CurrentVersionRun_719a {
  strings:
    $key_719a = { 22 f5 [2] 06 fb [2] 2d d7 [2] 03 f5 [2] 17 ee [2] 18 f4 [2] 06 e9 [2] 04 e8 [2] 1f ee [2] 03 e9 [2] 1f c6 }

  condition:
    any of them
}