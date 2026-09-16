rule TTP_XOR_MULT_DOSStub_7786 {
  strings:
    $key_7786 = { 23 ee [2] 57 f6 [2] 10 f4 [2] 57 e5 [2] 19 e9 [2] 15 e3 [2] 02 e8 [2] 19 a6 [2] 24 }

  condition:
    any of them
}