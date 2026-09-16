rule TTP_XOR_MULT_DOSStub_3499 {
  strings:
    $key_3499 = { 60 f1 [2] 14 e9 [2] 53 eb [2] 14 fa [2] 5a f6 [2] 56 fc [2] 41 f7 [2] 5a b9 [2] 67 }

  condition:
    any of them
}