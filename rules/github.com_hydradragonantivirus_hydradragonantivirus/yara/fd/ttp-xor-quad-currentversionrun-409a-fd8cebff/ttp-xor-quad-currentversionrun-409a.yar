rule TTP_XOR_QUAD_CurrentVersionRun_409a {
  strings:
    $key_409a = { 13 f5 [2] 37 fb [2] 1c d7 [2] 32 f5 [2] 26 ee [2] 29 f4 [2] 37 e9 [2] 35 e8 [2] 2e ee [2] 32 e9 [2] 2e c6 }

  condition:
    any of them
}