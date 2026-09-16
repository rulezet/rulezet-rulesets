rule TTP_XOR_QUAD_CurrentVersionRun_ea9a {
  strings:
    $key_ea9a = { b9 f5 [2] 9d fb [2] b6 d7 [2] 98 f5 [2] 8c ee [2] 83 f4 [2] 9d e9 [2] 9f e8 [2] 84 ee [2] 98 e9 [2] 84 c6 }

  condition:
    any of them
}