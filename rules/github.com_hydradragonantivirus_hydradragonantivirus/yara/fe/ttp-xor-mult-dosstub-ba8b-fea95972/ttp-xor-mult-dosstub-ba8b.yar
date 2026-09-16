rule TTP_XOR_MULT_DOSStub_ba8b {
  strings:
    $key_ba8b = { ee e3 [2] 9a fb [2] dd f9 [2] 9a e8 [2] d4 e4 [2] d8 ee [2] cf e5 [2] d4 ab [2] e9 }

  condition:
    any of them
}