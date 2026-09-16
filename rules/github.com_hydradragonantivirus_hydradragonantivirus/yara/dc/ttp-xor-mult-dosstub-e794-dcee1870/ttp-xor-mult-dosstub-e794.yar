rule TTP_XOR_MULT_DOSStub_e794 {
  strings:
    $key_e794 = { b3 fc [2] c7 e4 [2] 80 e6 [2] c7 f7 [2] 89 fb [2] 85 f1 [2] 92 fa [2] 89 b4 [2] b4 }

  condition:
    any of them
}