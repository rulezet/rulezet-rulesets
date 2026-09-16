rule TTP_XOR_MULT_DOSStub_4692 {
  strings:
    $key_4692 = { 12 fa [2] 66 e2 [2] 21 e0 [2] 66 f1 [2] 28 fd [2] 24 f7 [2] 33 fc [2] 28 b2 [2] 15 }

  condition:
    any of them
}