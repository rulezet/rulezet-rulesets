rule TTP_XOR_MULT_DOSStub_2693 {
  strings:
    $key_2693 = { 72 fb [2] 06 e3 [2] 41 e1 [2] 06 f0 [2] 48 fc [2] 44 f6 [2] 53 fd [2] 48 b3 [2] 75 }

  condition:
    any of them
}