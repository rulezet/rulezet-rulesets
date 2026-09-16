rule TTP_XOR_MULT_DOSStub_2a94 {
  strings:
    $key_2a94 = { 7e fc [2] 0a e4 [2] 4d e6 [2] 0a f7 [2] 44 fb [2] 48 f1 [2] 5f fa [2] 44 b4 [2] 79 }

  condition:
    any of them
}