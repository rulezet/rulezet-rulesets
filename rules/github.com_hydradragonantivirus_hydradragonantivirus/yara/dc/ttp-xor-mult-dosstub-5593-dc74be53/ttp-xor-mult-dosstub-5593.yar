rule TTP_XOR_MULT_DOSStub_5593 {
  strings:
    $key_5593 = { 01 fb [2] 75 e3 [2] 32 e1 [2] 75 f0 [2] 3b fc [2] 37 f6 [2] 20 fd [2] 3b b3 [2] 06 }

  condition:
    any of them
}