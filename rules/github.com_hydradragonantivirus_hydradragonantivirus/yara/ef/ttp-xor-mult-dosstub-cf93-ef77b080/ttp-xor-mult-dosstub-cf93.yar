rule TTP_XOR_MULT_DOSStub_cf93 {
  strings:
    $key_cf93 = { 9b fb [2] ef e3 [2] a8 e1 [2] ef f0 [2] a1 fc [2] ad f6 [2] ba fd [2] a1 b3 [2] 9c }

  condition:
    any of them
}