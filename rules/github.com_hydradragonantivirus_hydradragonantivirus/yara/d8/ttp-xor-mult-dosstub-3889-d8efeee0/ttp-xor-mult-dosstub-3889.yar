rule TTP_XOR_MULT_DOSStub_3889 {
  strings:
    $key_3889 = { 6c e1 [2] 18 f9 [2] 5f fb [2] 18 ea [2] 56 e6 [2] 5a ec [2] 4d e7 [2] 56 a9 [2] 6b }

  condition:
    any of them
}