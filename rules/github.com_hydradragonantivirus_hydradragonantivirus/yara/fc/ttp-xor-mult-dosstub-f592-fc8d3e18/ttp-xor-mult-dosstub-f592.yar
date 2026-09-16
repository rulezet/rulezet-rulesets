rule TTP_XOR_MULT_DOSStub_f592 {
  strings:
    $key_f592 = { a1 fa [2] d5 e2 [2] 92 e0 [2] d5 f1 [2] 9b fd [2] 97 f7 [2] 80 fc [2] 9b b2 [2] a6 }

  condition:
    any of them
}