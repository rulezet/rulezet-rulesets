rule TTP_XOR_MULT_DOSStub_5298 {
  strings:
    $key_5298 = { 06 f0 [2] 72 e8 [2] 35 ea [2] 72 fb [2] 3c f7 [2] 30 fd [2] 27 f6 [2] 3c b8 [2] 01 }

  condition:
    any of them
}