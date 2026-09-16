rule TTP_XOR_MULT_DOSStub_7289 {
  strings:
    $key_7289 = { 26 e1 [2] 52 f9 [2] 15 fb [2] 52 ea [2] 1c e6 [2] 10 ec [2] 07 e7 [2] 1c a9 [2] 21 }

  condition:
    any of them
}