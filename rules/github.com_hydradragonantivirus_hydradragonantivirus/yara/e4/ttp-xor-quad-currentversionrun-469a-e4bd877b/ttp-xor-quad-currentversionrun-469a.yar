rule TTP_XOR_QUAD_CurrentVersionRun_469a {
  strings:
    $key_469a = { 15 f5 [2] 31 fb [2] 1a d7 [2] 34 f5 [2] 20 ee [2] 2f f4 [2] 31 e9 [2] 33 e8 [2] 28 ee [2] 34 e9 [2] 28 c6 }

  condition:
    any of them
}