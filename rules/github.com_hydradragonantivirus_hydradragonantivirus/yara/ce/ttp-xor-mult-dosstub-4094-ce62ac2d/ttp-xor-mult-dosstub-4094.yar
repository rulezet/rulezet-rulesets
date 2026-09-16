rule TTP_XOR_MULT_DOSStub_4094 {
  strings:
    $key_4094 = { 14 fc [2] 60 e4 [2] 27 e6 [2] 60 f7 [2] 2e fb [2] 22 f1 [2] 35 fa [2] 2e b4 [2] 13 }

  condition:
    any of them
}