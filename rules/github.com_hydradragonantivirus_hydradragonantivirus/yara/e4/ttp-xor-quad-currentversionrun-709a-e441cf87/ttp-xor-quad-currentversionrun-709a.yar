rule TTP_XOR_QUAD_CurrentVersionRun_709a {
  strings:
    $key_709a = { 23 f5 [2] 07 fb [2] 2c d7 [2] 02 f5 [2] 16 ee [2] 19 f4 [2] 07 e9 [2] 05 e8 [2] 1e ee [2] 02 e9 [2] 1e c6 }

  condition:
    any of them
}