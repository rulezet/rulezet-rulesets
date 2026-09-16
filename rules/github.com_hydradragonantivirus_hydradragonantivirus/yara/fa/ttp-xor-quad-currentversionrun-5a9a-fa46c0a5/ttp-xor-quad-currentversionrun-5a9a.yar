rule TTP_XOR_QUAD_CurrentVersionRun_5a9a {
  strings:
    $key_5a9a = { 09 f5 [2] 2d fb [2] 06 d7 [2] 28 f5 [2] 3c ee [2] 33 f4 [2] 2d e9 [2] 2f e8 [2] 34 ee [2] 28 e9 [2] 34 c6 }

  condition:
    any of them
}