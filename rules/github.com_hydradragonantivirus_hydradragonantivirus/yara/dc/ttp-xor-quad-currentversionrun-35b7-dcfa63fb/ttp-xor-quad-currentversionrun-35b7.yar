rule TTP_XOR_QUAD_CurrentVersionRun_35b7 {
  strings:
    $key_35b7 = { 66 d8 [2] 42 d6 [2] 69 fa [2] 47 d8 [2] 53 c3 [2] 5c d9 [2] 42 c4 [2] 40 c5 [2] 5b c3 [2] 47 c4 [2] 5b eb }

  condition:
    any of them
}