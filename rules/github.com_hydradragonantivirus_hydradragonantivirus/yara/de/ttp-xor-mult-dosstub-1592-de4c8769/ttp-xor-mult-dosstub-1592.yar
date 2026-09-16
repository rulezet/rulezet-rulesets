rule TTP_XOR_MULT_DOSStub_1592 {
  strings:
    $key_1592 = { 41 fa [2] 35 e2 [2] 72 e0 [2] 35 f1 [2] 7b fd [2] 77 f7 [2] 60 fc [2] 7b b2 [2] 46 }

  condition:
    any of them
}