rule TTP_XOR_MULT_DOSStub_4793 {
  strings:
    $key_4793 = { 13 fb [2] 67 e3 [2] 20 e1 [2] 67 f0 [2] 29 fc [2] 25 f6 [2] 32 fd [2] 29 b3 [2] 14 }

  condition:
    any of them
}