rule TTP_XOR_MULT_DOSStub_0092 {
  strings:
    $key_0092 = { 54 fa [2] 20 e2 [2] 67 e0 [2] 20 f1 [2] 6e fd [2] 62 f7 [2] 75 fc [2] 6e b2 [2] 53 }

  condition:
    any of them
}