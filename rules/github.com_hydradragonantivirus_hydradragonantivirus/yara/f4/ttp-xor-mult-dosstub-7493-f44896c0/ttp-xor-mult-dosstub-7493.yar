rule TTP_XOR_MULT_DOSStub_7493 {
  strings:
    $key_7493 = { 20 fb [2] 54 e3 [2] 13 e1 [2] 54 f0 [2] 1a fc [2] 16 f6 [2] 01 fd [2] 1a b3 [2] 27 }

  condition:
    any of them
}