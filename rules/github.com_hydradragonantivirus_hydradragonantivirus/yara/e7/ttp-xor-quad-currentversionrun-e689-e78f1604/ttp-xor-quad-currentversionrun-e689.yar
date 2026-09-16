rule TTP_XOR_QUAD_CurrentVersionRun_e689 {
  strings:
    $key_e689 = { b5 e6 [2] 91 e8 [2] ba c4 [2] 94 e6 [2] 80 fd [2] 8f e7 [2] 91 fa [2] 93 fb [2] 88 fd [2] 94 fa [2] 88 d5 }

  condition:
    any of them
}