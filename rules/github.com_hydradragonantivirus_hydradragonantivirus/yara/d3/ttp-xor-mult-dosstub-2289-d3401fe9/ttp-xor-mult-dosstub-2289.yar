rule TTP_XOR_MULT_DOSStub_2289 {
  strings:
    $key_2289 = { 76 e1 [2] 02 f9 [2] 45 fb [2] 02 ea [2] 4c e6 [2] 40 ec [2] 57 e7 [2] 4c a9 [2] 71 }

  condition:
    any of them
}