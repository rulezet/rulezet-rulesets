rule TTP_XOR_MULT_DOSStub_5492 {
  strings:
    $key_5492 = { 00 fa [2] 74 e2 [2] 33 e0 [2] 74 f1 [2] 3a fd [2] 36 f7 [2] 21 fc [2] 3a b2 [2] 07 }

  condition:
    any of them
}