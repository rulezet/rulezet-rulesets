rule TTP_XOR_QUAD_CurrentVersionRun_2ab6 {
  strings:
    $key_2ab6 = { 79 d9 [2] 5d d7 [2] 76 fb [2] 58 d9 [2] 4c c2 [2] 43 d8 [2] 5d c5 [2] 5f c4 [2] 44 c2 [2] 58 c5 [2] 44 ea }

  condition:
    any of them
}