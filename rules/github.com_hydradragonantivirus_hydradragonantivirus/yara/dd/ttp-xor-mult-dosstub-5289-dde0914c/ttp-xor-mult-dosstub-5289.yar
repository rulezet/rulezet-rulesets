rule TTP_XOR_MULT_DOSStub_5289 {
  strings:
    $key_5289 = { 06 e1 [2] 72 f9 [2] 35 fb [2] 72 ea [2] 3c e6 [2] 30 ec [2] 27 e7 [2] 3c a9 [2] 01 }

  condition:
    any of them
}