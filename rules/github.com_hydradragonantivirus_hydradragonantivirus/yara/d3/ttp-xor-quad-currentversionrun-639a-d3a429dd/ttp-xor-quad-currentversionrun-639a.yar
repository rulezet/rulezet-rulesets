rule TTP_XOR_QUAD_CurrentVersionRun_639a {
  strings:
    $key_639a = { 30 f5 [2] 14 fb [2] 3f d7 [2] 11 f5 [2] 05 ee [2] 0a f4 [2] 14 e9 [2] 16 e8 [2] 0d ee [2] 11 e9 [2] 0d c6 }

  condition:
    any of them
}