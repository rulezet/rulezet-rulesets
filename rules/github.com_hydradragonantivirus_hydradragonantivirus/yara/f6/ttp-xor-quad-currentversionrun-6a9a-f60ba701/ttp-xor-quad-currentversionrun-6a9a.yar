rule TTP_XOR_QUAD_CurrentVersionRun_6a9a {
  strings:
    $key_6a9a = { 39 f5 [2] 1d fb [2] 36 d7 [2] 18 f5 [2] 0c ee [2] 03 f4 [2] 1d e9 [2] 1f e8 [2] 04 ee [2] 18 e9 [2] 04 c6 }

  condition:
    any of them
}