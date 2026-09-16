rule TTP_XOR_MULT_DOSStub_f092 {
  strings:
    $key_f092 = { a4 fa [2] d0 e2 [2] 97 e0 [2] d0 f1 [2] 9e fd [2] 92 f7 [2] 85 fc [2] 9e b2 [2] a3 }

  condition:
    any of them
}