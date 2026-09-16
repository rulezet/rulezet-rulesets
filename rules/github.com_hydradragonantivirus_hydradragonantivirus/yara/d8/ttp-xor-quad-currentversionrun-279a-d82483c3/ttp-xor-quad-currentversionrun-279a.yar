rule TTP_XOR_QUAD_CurrentVersionRun_279a {
  strings:
    $key_279a = { 74 f5 [2] 50 fb [2] 7b d7 [2] 55 f5 [2] 41 ee [2] 4e f4 [2] 50 e9 [2] 52 e8 [2] 49 ee [2] 55 e9 [2] 49 c6 }

  condition:
    any of them
}