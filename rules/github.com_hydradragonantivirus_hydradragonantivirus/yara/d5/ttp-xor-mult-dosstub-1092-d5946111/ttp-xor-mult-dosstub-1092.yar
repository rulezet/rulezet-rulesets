rule TTP_XOR_MULT_DOSStub_1092 {
  strings:
    $key_1092 = { 44 fa [2] 30 e2 [2] 77 e0 [2] 30 f1 [2] 7e fd [2] 72 f7 [2] 65 fc [2] 7e b2 [2] 43 }

  condition:
    any of them
}