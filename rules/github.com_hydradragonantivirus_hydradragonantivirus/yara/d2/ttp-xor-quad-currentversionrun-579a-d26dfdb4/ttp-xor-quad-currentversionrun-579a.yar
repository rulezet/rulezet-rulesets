rule TTP_XOR_QUAD_CurrentVersionRun_579a {
  strings:
    $key_579a = { 04 f5 [2] 20 fb [2] 0b d7 [2] 25 f5 [2] 31 ee [2] 3e f4 [2] 20 e9 [2] 22 e8 [2] 39 ee [2] 25 e9 [2] 39 c6 }

  condition:
    any of them
}