rule TTP_XOR_MULT_DOSStub_7389 {
  strings:
    $key_7389 = { 27 e1 [2] 53 f9 [2] 14 fb [2] 53 ea [2] 1d e6 [2] 11 ec [2] 06 e7 [2] 1d a9 [2] 20 }

  condition:
    any of them
}