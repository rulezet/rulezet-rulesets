rule TTP_XOR_MULT_DOSStub_c194 {
  strings:
    $key_c194 = { 95 fc [2] e1 e4 [2] a6 e6 [2] e1 f7 [2] af fb [2] a3 f1 [2] b4 fa [2] af b4 [2] 92 }

  condition:
    any of them
}