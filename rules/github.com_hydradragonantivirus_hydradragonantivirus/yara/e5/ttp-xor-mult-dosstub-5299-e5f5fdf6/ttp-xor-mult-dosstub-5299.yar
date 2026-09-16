rule TTP_XOR_MULT_DOSStub_5299 {
  strings:
    $key_5299 = { 06 f1 [2] 72 e9 [2] 35 eb [2] 72 fa [2] 3c f6 [2] 30 fc [2] 27 f7 [2] 3c b9 [2] 01 }

  condition:
    any of them
}