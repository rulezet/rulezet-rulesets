rule TTP_XOR_MULT_DOSStub_ba89 {
  strings:
    $key_ba89 = { ee e1 [2] 9a f9 [2] dd fb [2] 9a ea [2] d4 e6 [2] d8 ec [2] cf e7 [2] d4 a9 [2] e9 }

  condition:
    any of them
}