rule TTP_XOR_QUAD_CurrentVersionRun_209a {
  strings:
    $key_209a = { 73 f5 [2] 57 fb [2] 7c d7 [2] 52 f5 [2] 46 ee [2] 49 f4 [2] 57 e9 [2] 55 e8 [2] 4e ee [2] 52 e9 [2] 4e c6 }

  condition:
    any of them
}