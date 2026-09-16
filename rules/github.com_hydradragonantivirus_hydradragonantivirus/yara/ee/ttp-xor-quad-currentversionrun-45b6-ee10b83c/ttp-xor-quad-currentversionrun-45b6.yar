rule TTP_XOR_QUAD_CurrentVersionRun_45b6 {
  strings:
    $key_45b6 = { 16 d9 [2] 32 d7 [2] 19 fb [2] 37 d9 [2] 23 c2 [2] 2c d8 [2] 32 c5 [2] 30 c4 [2] 2b c2 [2] 37 c5 [2] 2b ea }

  condition:
    any of them
}