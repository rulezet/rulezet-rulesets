rule TTP_XOR_MULT_DOSStub_5692 {
  strings:
    $key_5692 = { 02 fa [2] 76 e2 [2] 31 e0 [2] 76 f1 [2] 38 fd [2] 34 f7 [2] 23 fc [2] 38 b2 [2] 05 }

  condition:
    any of them
}