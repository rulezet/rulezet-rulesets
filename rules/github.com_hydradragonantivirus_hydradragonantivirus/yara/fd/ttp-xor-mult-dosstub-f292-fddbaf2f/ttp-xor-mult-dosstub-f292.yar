rule TTP_XOR_MULT_DOSStub_f292 {
  strings:
    $key_f292 = { a6 fa [2] d2 e2 [2] 95 e0 [2] d2 f1 [2] 9c fd [2] 90 f7 [2] 87 fc [2] 9c b2 [2] a1 }

  condition:
    any of them
}