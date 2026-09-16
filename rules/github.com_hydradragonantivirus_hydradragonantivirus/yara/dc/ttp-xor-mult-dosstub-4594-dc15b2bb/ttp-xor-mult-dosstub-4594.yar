rule TTP_XOR_MULT_DOSStub_4594 {
  strings:
    $key_4594 = { 11 fc [2] 65 e4 [2] 22 e6 [2] 65 f7 [2] 2b fb [2] 27 f1 [2] 30 fa [2] 2b b4 [2] 16 }

  condition:
    any of them
}