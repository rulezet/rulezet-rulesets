rule TTP_XOR_MULT_DOSStub_7a94 {
  strings:
    $key_7a94 = { 2e fc [2] 5a e4 [2] 1d e6 [2] 5a f7 [2] 14 fb [2] 18 f1 [2] 0f fa [2] 14 b4 [2] 29 }

  condition:
    any of them
}