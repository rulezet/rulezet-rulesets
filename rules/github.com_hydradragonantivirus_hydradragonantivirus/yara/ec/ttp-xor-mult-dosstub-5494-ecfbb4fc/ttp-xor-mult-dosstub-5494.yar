rule TTP_XOR_MULT_DOSStub_5494 {
  strings:
    $key_5494 = { 00 fc [2] 74 e4 [2] 33 e6 [2] 74 f7 [2] 3a fb [2] 36 f1 [2] 21 fa [2] 3a b4 [2] 07 }

  condition:
    any of them
}