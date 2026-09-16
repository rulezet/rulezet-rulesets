rule TTP_XOR_QUAD_CurrentVersionRun_1a9a {
  strings:
    $key_1a9a = { 49 f5 [2] 6d fb [2] 46 d7 [2] 68 f5 [2] 7c ee [2] 73 f4 [2] 6d e9 [2] 6f e8 [2] 74 ee [2] 68 e9 [2] 74 c6 }

  condition:
    any of them
}