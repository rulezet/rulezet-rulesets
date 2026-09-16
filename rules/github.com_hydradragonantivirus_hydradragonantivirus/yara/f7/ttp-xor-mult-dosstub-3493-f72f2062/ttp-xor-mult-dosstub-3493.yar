rule TTP_XOR_MULT_DOSStub_3493 {
  strings:
    $key_3493 = { 60 fb [2] 14 e3 [2] 53 e1 [2] 14 f0 [2] 5a fc [2] 56 f6 [2] 41 fd [2] 5a b3 [2] 67 }

  condition:
    any of them
}