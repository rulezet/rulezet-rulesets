rule TTP_XOR_MULT_DOSStub_8894 {
  strings:
    $key_8894 = { dc fc [2] a8 e4 [2] ef e6 [2] a8 f7 [2] e6 fb [2] ea f1 [2] fd fa [2] e6 b4 [2] db }

  condition:
    any of them
}