rule TTP_XOR_MULT_DOSStub_4092 {
  strings:
    $key_4092 = { 14 fa [2] 60 e2 [2] 27 e0 [2] 60 f1 [2] 2e fd [2] 22 f7 [2] 35 fc [2] 2e b2 [2] 13 }

  condition:
    any of them
}