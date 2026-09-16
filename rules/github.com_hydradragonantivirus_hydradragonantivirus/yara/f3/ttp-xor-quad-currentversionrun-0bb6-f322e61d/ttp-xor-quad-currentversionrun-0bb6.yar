rule TTP_XOR_QUAD_CurrentVersionRun_0bb6 {
  strings:
    $key_0bb6 = { 58 d9 [2] 7c d7 [2] 57 fb [2] 79 d9 [2] 6d c2 [2] 62 d8 [2] 7c c5 [2] 7e c4 [2] 65 c2 [2] 79 c5 [2] 65 ea }

  condition:
    any of them
}