rule TTP_XOR_MULT_DOSStub_3293 {
  strings:
    $key_3293 = { 66 fb [2] 12 e3 [2] 55 e1 [2] 12 f0 [2] 5c fc [2] 50 f6 [2] 47 fd [2] 5c b3 [2] 61 }

  condition:
    any of them
}