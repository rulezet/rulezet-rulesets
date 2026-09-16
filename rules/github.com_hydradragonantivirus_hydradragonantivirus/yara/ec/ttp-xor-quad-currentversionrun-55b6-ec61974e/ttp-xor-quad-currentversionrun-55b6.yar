rule TTP_XOR_QUAD_CurrentVersionRun_55b6 {
  strings:
    $key_55b6 = { 06 d9 [2] 22 d7 [2] 09 fb [2] 27 d9 [2] 33 c2 [2] 3c d8 [2] 22 c5 [2] 20 c4 [2] 3b c2 [2] 27 c5 [2] 3b ea }

  condition:
    any of them
}