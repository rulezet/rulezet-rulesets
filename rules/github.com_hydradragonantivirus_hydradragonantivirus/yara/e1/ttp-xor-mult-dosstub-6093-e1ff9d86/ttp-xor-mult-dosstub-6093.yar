rule TTP_XOR_MULT_DOSStub_6093 {
  strings:
    $key_6093 = { 34 fb [2] 40 e3 [2] 07 e1 [2] 40 f0 [2] 0e fc [2] 02 f6 [2] 15 fd [2] 0e b3 [2] 33 }

  condition:
    any of them
}