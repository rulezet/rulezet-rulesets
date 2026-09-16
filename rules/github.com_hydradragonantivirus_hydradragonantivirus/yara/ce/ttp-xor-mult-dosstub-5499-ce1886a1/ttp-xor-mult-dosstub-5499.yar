rule TTP_XOR_MULT_DOSStub_5499 {
  strings:
    $key_5499 = { 00 f1 [2] 74 e9 [2] 33 eb [2] 74 fa [2] 3a f6 [2] 36 fc [2] 21 f7 [2] 3a b9 [2] 07 }

  condition:
    any of them
}