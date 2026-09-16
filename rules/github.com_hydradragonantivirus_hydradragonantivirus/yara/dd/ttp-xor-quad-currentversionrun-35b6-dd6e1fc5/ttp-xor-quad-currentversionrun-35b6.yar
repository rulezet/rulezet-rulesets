rule TTP_XOR_QUAD_CurrentVersionRun_35b6 {
  strings:
    $key_35b6 = { 66 d9 [2] 42 d7 [2] 69 fb [2] 47 d9 [2] 53 c2 [2] 5c d8 [2] 42 c5 [2] 40 c4 [2] 5b c2 [2] 47 c5 [2] 5b ea }

  condition:
    any of them
}