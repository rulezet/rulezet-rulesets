rule TTP_XOR_QUAD_CurrentVersionRun_65b6 {
  strings:
    $key_65b6 = { 36 d9 [2] 12 d7 [2] 39 fb [2] 17 d9 [2] 03 c2 [2] 0c d8 [2] 12 c5 [2] 10 c4 [2] 0b c2 [2] 17 c5 [2] 0b ea }

  condition:
    any of them
}