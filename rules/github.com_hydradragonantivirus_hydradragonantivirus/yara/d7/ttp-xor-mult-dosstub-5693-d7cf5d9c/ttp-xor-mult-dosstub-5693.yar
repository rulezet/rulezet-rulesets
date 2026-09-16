rule TTP_XOR_MULT_DOSStub_5693 {
  strings:
    $key_5693 = { 02 fb [2] 76 e3 [2] 31 e1 [2] 76 f0 [2] 38 fc [2] 34 f6 [2] 23 fd [2] 38 b3 [2] 05 }

  condition:
    any of them
}