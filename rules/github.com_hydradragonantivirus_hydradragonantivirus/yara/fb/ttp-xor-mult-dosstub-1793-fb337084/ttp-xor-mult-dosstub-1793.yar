rule TTP_XOR_MULT_DOSStub_1793 {
  strings:
    $key_1793 = { 43 fb [2] 37 e3 [2] 70 e1 [2] 37 f0 [2] 79 fc [2] 75 f6 [2] 62 fd [2] 79 b3 [2] 44 }

  condition:
    any of them
}