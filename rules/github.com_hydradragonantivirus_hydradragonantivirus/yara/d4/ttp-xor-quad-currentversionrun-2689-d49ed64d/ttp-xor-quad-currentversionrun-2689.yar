rule TTP_XOR_QUAD_CurrentVersionRun_2689 {
  strings:
    $key_2689 = { 75 e6 [2] 51 e8 [2] 7a c4 [2] 54 e6 [2] 40 fd [2] 4f e7 [2] 51 fa [2] 53 fb [2] 48 fd [2] 54 fa [2] 48 d5 }

  condition:
    any of them
}