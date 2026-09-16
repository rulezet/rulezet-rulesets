rule TTP_XOR_MULT_DOSStub_1798 {
  strings:
    $key_1798 = { 43 f0 [2] 37 e8 [2] 70 ea [2] 37 fb [2] 79 f7 [2] 75 fd [2] 62 f6 [2] 79 b8 [2] 44 }

  condition:
    any of them
}