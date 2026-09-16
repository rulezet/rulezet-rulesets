rule TTP_XOR_MULT_DOSStub_2293 {
  strings:
    $key_2293 = { 76 fb [2] 02 e3 [2] 45 e1 [2] 02 f0 [2] 4c fc [2] 40 f6 [2] 57 fd [2] 4c b3 [2] 71 }

  condition:
    any of them
}