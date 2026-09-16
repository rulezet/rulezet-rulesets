rule TTP_XOR_MULT_DOSStub_4889 {
  strings:
    $key_4889 = { 1c e1 [2] 68 f9 [2] 2f fb [2] 68 ea [2] 26 e6 [2] 2a ec [2] 3d e7 [2] 26 a9 [2] 1b }

  condition:
    any of them
}