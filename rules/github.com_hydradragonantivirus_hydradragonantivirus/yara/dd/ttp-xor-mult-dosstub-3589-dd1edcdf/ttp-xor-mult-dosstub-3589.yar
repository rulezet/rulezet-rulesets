rule TTP_XOR_MULT_DOSStub_3589 {
  strings:
    $key_3589 = { 61 e1 [2] 15 f9 [2] 52 fb [2] 15 ea [2] 5b e6 [2] 57 ec [2] 40 e7 [2] 5b a9 [2] 66 }

  condition:
    any of them
}