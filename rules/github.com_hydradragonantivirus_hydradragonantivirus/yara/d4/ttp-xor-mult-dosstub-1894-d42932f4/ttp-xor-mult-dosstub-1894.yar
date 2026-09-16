rule TTP_XOR_MULT_DOSStub_1894 {
  strings:
    $key_1894 = { 4c fc [2] 38 e4 [2] 7f e6 [2] 38 f7 [2] 76 fb [2] 7a f1 [2] 6d fa [2] 76 b4 [2] 4b }

  condition:
    any of them
}