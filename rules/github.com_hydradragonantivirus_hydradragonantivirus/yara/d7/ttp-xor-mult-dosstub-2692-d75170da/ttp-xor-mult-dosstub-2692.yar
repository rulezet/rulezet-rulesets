rule TTP_XOR_MULT_DOSStub_2692 {
  strings:
    $key_2692 = { 72 fa [2] 06 e2 [2] 41 e0 [2] 06 f1 [2] 48 fd [2] 44 f7 [2] 53 fc [2] 48 b2 [2] 75 }

  condition:
    any of them
}