rule TTP_XOR_MULT_DOSStub_3592 {
  strings:
    $key_3592 = { 61 fa [2] 15 e2 [2] 52 e0 [2] 15 f1 [2] 5b fd [2] 57 f7 [2] 40 fc [2] 5b b2 [2] 66 }

  condition:
    any of them
}